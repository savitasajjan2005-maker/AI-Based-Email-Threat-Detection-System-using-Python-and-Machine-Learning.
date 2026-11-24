from history import (
    create_history_table,
    save_scan,
    get_history,
    get_analytics
)

import plotly.express as px
import pandas as pd
from history import create_history_table, save_scan, get_history

create_history_table()
from pathlib import Path
import hashlib
import hmac
import re
import secrets
import sqlite3

import joblib
import streamlit as st

ROOT = Path(__file__).resolve().parent
MODEL = ROOT / "models" / "email_detector.joblib"
DB_PATH = ROOT / "users.db"

st.set_page_config(
    page_title="AI Email Threat Detector",
    page_icon="🛡️"
)


# ---------------- DATABASE ----------------

def get_connection():
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    return conn


# ---------------- PASSWORD SECURITY ----------------

def hash_password(password, salt_hex=None):
    salt = (
        bytes.fromhex(salt_hex)
        if salt_hex
        else secrets.token_bytes(16)
    )

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        310000
    )

    return salt.hex(), hashed.hex()


def verify_password(password, salt, stored_hash):
    _, candidate = hash_password(password, salt)

    return hmac.compare_digest(
        candidate,
        stored_hash
    )


def register_user(email, password):
    salt, hashed = hash_password(password)

    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users
                (email, salt, password_hash)
                VALUES (?, ?, ?)
                """,
                (email.lower().strip(), salt, hashed)
            )

        return True, "Registration successful!"

    except sqlite3.IntegrityError:
        return False, "Email already registered."


def authenticate_user(email, password):
    with get_connection() as conn:
        user = conn.execute(
            """
            SELECT salt, password_hash
            FROM users
            WHERE email = ?
            """,
            (email.lower().strip(),)
        ).fetchone()

    if user:
        return verify_password(
            password,
            user[0],
            user[1]
        )

    return False


# ---------------- CAPTCHA ----------------

def generate_captcha():
    a = secrets.randbelow(8) + 2
    b = secrets.randbelow(8) + 2

    return {
        "question": f"{a} + {b}",
        "answer": str(a + b)
    }


for key in ["login_captcha", "register_captcha"]:
    if key not in st.session_state:
        st.session_state[key] = generate_captcha()


# ---------------- LOGIN / REGISTER ----------------

def show_authentication():

    st.title("🛡️ AI Email Threat Detector")
    st.caption("Secure User Authentication")

    login_tab, register_tab = st.tabs(
        ["Login", "Register"]
    )

    # LOGIN
    with login_tab:

        st.subheader("Welcome Back")

        with st.form("login_form"):

            email = st.text_input("Email Address")

            password = st.text_input(
                "Password",
                type="password"
            )

            st.write(
                "CAPTCHA:",
                st.session_state["login_captcha"]["question"],
                "= ?"
            )

            answer = st.text_input("Enter CAPTCHA answer")

            submitted = st.form_submit_button(
                "Login",
                type="primary"
            )

        if submitted:

            if not email or not password:
                st.warning("Enter email and password.")

            elif answer.strip() != st.session_state[
                "login_captcha"
            ]["answer"]:

                st.error("Incorrect CAPTCHA.")

                st.session_state["login_captcha"] = generate_captcha()
                st.rerun()

            elif authenticate_user(email, password):

                st.session_state["authenticated"] = True
                st.session_state["user_email"] = email.lower().strip()

                st.success("Login successful!")
                st.rerun()

            else:

                st.error("Invalid email or password.")

                st.session_state["login_captcha"] = generate_captcha()
                st.rerun()

        if st.button("Refresh Login CAPTCHA"):
            st.session_state["login_captcha"] = generate_captcha()
            st.rerun()

    # REGISTER
    with register_tab:

        st.subheader("Create New Account")

        with st.form("register_form"):

            new_email = st.text_input(
                "Email Address",
                key="register_email"
            )

            new_password = st.text_input(
                "Create Password",
                type="password"
            )

            confirm_password = st.text_input(
                "Confirm Password",
                type="password"
            )

            st.write(
                "CAPTCHA:",
                st.session_state["register_captcha"]["question"],
                "= ?"
            )

            captcha_answer = st.text_input(
                "Enter CAPTCHA answer",
                key="register_answer"
            )

            submitted = st.form_submit_button(
                "Create Account",
                type="primary"
            )

        if submitted:

            if (
                not new_email
                or "@" not in new_email
                or "." not in new_email.rsplit("@", 1)[-1]
            ):
                st.warning("Enter a valid email address.")

            elif len(new_password) < 8:
                st.warning(
                    "Password must contain at least 8 characters."
                )

            elif new_password != confirm_password:
                st.warning("Passwords do not match.")

            elif captcha_answer.strip() != st.session_state[
                "register_captcha"
            ]["answer"]:

                st.error("Incorrect CAPTCHA.")

                st.session_state["register_captcha"] = generate_captcha()
                st.rerun()

            else:

                success, message = register_user(
                    new_email,
                    new_password
                )

                if success:
                    st.success(message)

                    st.session_state["register_captcha"] = generate_captcha()

                else:
                    st.error(message)

        if st.button("Refresh Registration CAPTCHA"):
            st.session_state["register_captcha"] = generate_captcha()
            st.rerun()
    
    st.divider()

    st.caption(
        "Educational authentication system."
    )


# ---------------- LOAD AI MODEL ----------------

@st.cache_resource
def load_model():

    if not MODEL.exists():
        raise FileNotFoundError(
            "Model missing. Run python train_model.py first."
        )

    return joblib.load(MODEL)


# ---------------- PHISHING DETECTION ----------------

terms = [
    "urgent",
    "verify",
    "password",
    "otp",
    "suspended",
    "blocked",
    "claim",
    "prize",
    "gift card",
    "click here",
    "bank details",
    "credit card",
    "kyc",
    "immediately",
    "final warning",
    "confirm your identity"
]


def inspect_email(text):

    low = text.lower()

    found = sorted({
        term for term in terms
        if term in low
    })

    urls = re.findall(
        r"https?://\S+|www\.\S+",
        text,
        flags=re.I
    )

    score = min(len(found) * 8, 48)
    score += min(len(urls) * 12, 24)

    if re.search(
        r"https?://(?:\d{1,3}\.){3}\d{1,3}",
        text,
        re.I
    ):
        score += 20

    if re.search(
        r"\b(password|otp|credit card|bank details)\b",
        low
    ):
        score += 15

    if re.search(
        r"\b(urgent|immediately|final warning)\b",
        low
    ):
        score += 10

    return min(score, 100), found, urls


# ---------------- MAIN DASHBOARD ----------------

def show_dashboard():

    st.title("🛡️ AI Email Threat Detector")

    st.write(
        "Paste an email to estimate whether it may be phishing or legitimate."
    )

    st.info(
        "Educational prototype only. Do not paste real passwords, "
        "OTPs, or confidential information."
    )

    col1, col2 = st.columns([3, 1])

    col1.write(
        f"Logged in as: {st.session_state['user_email']}"
    )

    if col2.button("Logout"):

        st.session_state["authenticated"] = False
        st.session_state.pop("user_email", None)

        st.rerun()

    try:
        model = load_model()

    except Exception as error:

        st.error(str(error))
        st.code("python train_model.py")
        st.stop()

    message = st.text_area(
        "Email Subject and Body",
        height=220,
        placeholder="Paste email text here..."
    )

    if st.button("Analyse Email", type="primary"):

        if len(message.strip()) < 15:

            st.warning("Enter a longer email message.")

        else:

            pred = model.predict([message])[0]

            probs = model.predict_proba([message])[0]

            phishing_prob = float(
                probs[
                    list(model.classes_).index("phishing")
                ]
            )

            rule_score, found, urls = inspect_email(message)

            score = round(
                phishing_prob * 70 + rule_score * 0.30
            )

            risk = pred == "phishing" or score >= 55
            save_scan(
                st.session_state.get("email", "Unknown"),
                pred,
                score
            )

            st.subheader("Result")

            if risk:
                st.error("⚠️ Potential phishing email")

            else:
                st.success("✅ Likely legitimate email")

            a, b, c = st.columns(3)

            a.metric("Threat Score", f"{score}/100")

            b.metric(
                "ML Phishing Score",
                f"{phishing_prob:.0%}"
            )

            c.metric(
                "Links Detected",
                len(urls)
            )

            st.progress(score / 100)

            st.caption(
                "Threat score is an educational estimate, "
                "not a calibrated probability."
            )

            with st.expander(
                "Why did the system produce this result?",
                expanded=True
            ):

                st.write(
                    "**ML Prediction:**",
                    str(pred).title()
                )

                st.write(
                    "**Risk Terms:**",
                    ", ".join(found) if found else "None found"
                )

                st.write("**URLs:**")

                if urls:

                    for url in urls:
                        st.code(url)

                else:
                    st.write("No URLs detected.")

                st.write(
                    "The model uses TF-IDF text features and "
                    "Logistic Regression."
                )

            if risk:

                st.warning(
                    "Do not click links, open unexpected attachments, "
                    "or share passwords/OTPs. Verify requests independently."
                )

            else:

                st.info(
                    "A legitimate-looking result does not guarantee safety."
                )
    
    # Security Analytics Dashboard

    st.divider()
    st.header("📊 Security Analytics Dashboard")

    analytics = get_analytics()

    phishing_count = analytics.get("phishing", 0)
    legitimate_count = analytics.get("legitimate", 0)

    total_scans = phishing_count + legitimate_count

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Emails Scanned", total_scans)
    col2.metric("Phishing Detected", phishing_count)
    col3.metric("Legitimate Emails", legitimate_count)

    if total_scans > 0:

        phishing_percentage = (
            phishing_count / total_scans
        ) * 100

        st.metric(
            "Phishing Detection Percentage",
            f"{phishing_percentage:.1f}%"
        )

        chart_data = pd.DataFrame({
            "Email Type": ["Phishing", "Legitimate"],
            "Count": [phishing_count, legitimate_count]
        })

        fig = px.pie(
            chart_data,
            names="Email Type",
            values="Count",
            title="Email Threat Distribution",
            hole=0.4
        )

        st.plotly_chart(fig, use_container_width=True)

    else:
        st.info("Analyse some emails to view analytics.")

    # Email Scan History
    st.divider()
    st.subheader("📜 Email Scan History")

    history = get_history()

    if history:
        for record in history:
            st.write("Prediction:", record[2])
            st.write("Threat Score:", record[3])
            st.write("Date:", record[4])
            st.divider()
    else:
        st.info("No scan history available.")

    st.caption(
        "Demo model trained on a small sample dataset. "
        "Not suitable for real-world security decisions."
    )

    st.divider()

    st.caption(
        "Demo model trained on a small sample dataset. "
        "Not suitable for real-world security decisions."
    )


# ---------------- APPLICATION ENTRY ----------------

if st.session_state.get("authenticated", False):

    show_dashboard()

else:

    show_authentication()
