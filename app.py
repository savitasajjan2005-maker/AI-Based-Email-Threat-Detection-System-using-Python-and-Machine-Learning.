from pathlib import Path
import hashlib
import hmac
import re
import secrets
import sqlite3

import joblib
import pandas as pd
import plotly.express as px
import streamlit as st

from history import create_history_table, save_scan, get_history, get_analytics


# ---------------- CONFIGURATION ----------------

ROOT = Path(__file__).resolve().parent
MODEL = ROOT / "models" / "email_detector.joblib"
DB_PATH = ROOT / "users.db"

st.set_page_config(
    page_title="SecureMail AI | Email Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ---------------- MODERN UI STYLING ----------------

st.markdown(
    """
    <style>
    .stApp {
        background:
            radial-gradient(circle at 15% 20%, #25205a 0%, transparent 35%),
            radial-gradient(circle at 85% 80%, #172e55 0%, transparent 35%),
            #080d1b;
        color: #f8fafc;
    }
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    .hero-panel {
        min-height: 590px; padding: 45px 35px; border-radius: 28px;
        background: linear-gradient(145deg, rgba(91,75,210,.28), rgba(19,30,58,.75));
        border: 1px solid rgba(255,255,255,.12);
        display: flex; flex-direction: column; justify-content: center;
    }
    .brand-logo { font-size: 46px; margin-bottom: 18px; }
    .brand-name { font-size: 25px; font-weight: 800; letter-spacing: .5px; }
    .hero-title { font-size: 42px; line-height: 1.2; font-weight: 800; margin: 35px 0 18px; }
    .hero-title span { color: #a78bfa; }
    .hero-description { color: #cbd5e1; font-size: 16px; line-height: 1.8; }
    .feature-item {
        background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.08);
        padding: 13px 16px; border-radius: 14px; margin-top: 12px; color: #e2e8f0;
    }
    .stTextInput input {
        background: #111a2e !important; color: #fff !important;
        border: 1px solid #293650 !important; border-radius: 12px !important;
        padding: 12px !important;
    }
    .stTextInput input:focus {
        border: 1px solid #8b5cf6 !important;
        box-shadow: 0 0 0 2px rgba(139,92,246,.2) !important;
    }
    .stButton button, .stFormSubmitButton button {
        border-radius: 12px !important; min-height: 45px; font-weight: 700 !important;
        border: none !important; background: linear-gradient(90deg,#6d5dfc,#9333ea) !important;
        color: white !important; transition: .2s ease;
    }
    .stButton button:hover, .stFormSubmitButton button:hover {
        transform: translateY(-2px); box-shadow: 0 8px 25px rgba(124,58,237,.35);
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px; background: #111a2e; padding: 7px; border-radius: 14px;
    }
    .stTabs [data-baseweb="tab"] { border-radius: 10px; color: #cbd5e1; }
    .stTabs [aria-selected="true"] { background: #6d5dfc !important; color: white !important; }
    #MainMenu, footer { visibility: hidden; }
    @media (max-width: 800px) {
        .hero-panel { min-height: auto; padding: 28px; }
        .hero-title { font-size: 32px; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------- DATABASE ----------------

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    return conn


create_history_table()


# ---------------- PASSWORD SECURITY ----------------

def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 310000
    )
    return salt.hex(), hashed.hex()


def verify_password(password, salt, stored_hash):
    _, candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, stored_hash)


def register_user(email, password):
    salt, hashed = hash_password(password)
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (email, salt, password_hash) VALUES (?, ?, ?)",
                (email.lower().strip(), salt, hashed),
            )
        return True, "Registration successful! You can now sign in."
    except sqlite3.IntegrityError:
        return False, "Email already registered."


def authenticate_user(email, password):
    with get_connection() as conn:
        user = conn.execute(
            "SELECT salt, password_hash FROM users WHERE email = ?",
            (email.lower().strip(),),
        ).fetchone()
    if user:
        return verify_password(password, user[0], user[1])
    return False


# ---------------- CAPTCHA ----------------

def generate_captcha():
    a = secrets.randbelow(8) + 2
    b = secrets.randbelow(8) + 2
    return {"question": f"{a} + {b}", "answer": str(a + b)}


for captcha_key in ("login_captcha", "register_captcha"):
    if captcha_key not in st.session_state:
        st.session_state[captcha_key] = generate_captcha()


# ---------------- LOGIN / REGISTER ----------------

def show_authentication():
    left_col, right_col = st.columns(
        [1.15, 0.85], gap="large", vertical_alignment="center"
    )

    with left_col:
        st.markdown(
            """
            <div class="hero-panel">
                <div class="brand-logo">🛡️</div>
                <div class="brand-name">SecureMail <span style="color:#a78bfa">AI</span></div>
                <div class="hero-title">Stay ahead of<br><span>email threats.</span></div>
                <div class="hero-description">
                    Protect your inbox with intelligent AI-powered email threat
                    detection and security insights.
                </div>
                <div class="feature-item">🔍 &nbsp; AI-powered phishing detection</div>
                <div class="feature-item">🔐 &nbsp; Secure user authentication</div>
                <div class="feature-item">📊 &nbsp; Email security analytics</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with right_col:
        st.markdown(
            """
            <div style="text-align:center; margin-bottom:20px;">
                <div style="font-size:38px;">🔐</div>
                <h2 style="margin-bottom:5px;">Welcome back</h2>
                <p style="color:#94a3b8;">Sign in to your security dashboard</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        login_tab, register_tab = st.tabs(["Sign In", "Create Account"])

        with login_tab:
            with st.form("login_form"):
                email = st.text_input("Email Address", placeholder="you@example.com")
                password = st.text_input(
                    "Password", type="password", placeholder="Enter your password"
                )
                st.markdown(
                    f"**CAPTCHA:** {st.session_state['login_captcha']['question']} = ?"
                )
                answer = st.text_input("CAPTCHA answer")
                submitted = st.form_submit_button(
                    "Sign In →", type="primary", use_container_width=True
                )

            if submitted:
                if not email.strip() or not password:
                    st.warning("Enter email and password.")
                elif answer.strip() != st.session_state["login_captcha"]["answer"]:
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

            if st.button("🔄 Refresh CAPTCHA", key="refresh_login_captcha", use_container_width=True):
                st.session_state["login_captcha"] = generate_captcha()
                st.rerun()

        with register_tab:
            with st.form("register_form"):
                new_email = st.text_input(
                    "Email Address", key="register_email", placeholder="you@example.com"
                )
                new_password = st.text_input(
                    "Create Password", type="password", placeholder="At least 8 characters"
                )
                confirm_password = st.text_input("Confirm Password", type="password")
                st.markdown(
                    f"**CAPTCHA:** {st.session_state['register_captcha']['question']} = ?"
                )
                captcha_answer = st.text_input("CAPTCHA answer", key="register_answer")
                submitted = st.form_submit_button(
                    "Create Account →", type="primary", use_container_width=True
                )

            if submitted:
                if (
                    not new_email
                    or "@" not in new_email
                    or "." not in new_email.rsplit("@", 1)[-1]
                ):
                    st.warning("Enter a valid email address.")
                elif len(new_password) < 8:
                    st.warning("Password must contain at least 8 characters.")
                elif new_password != confirm_password:
                    st.warning("Passwords do not match.")
                elif captcha_answer.strip() != st.session_state["register_captcha"]["answer"]:
                    st.error("Incorrect CAPTCHA.")
                    st.session_state["register_captcha"] = generate_captcha()
                    st.rerun()
                else:
                    success, message = register_user(new_email, new_password)
                    if success:
                        st.success(message)
                        st.session_state["register_captcha"] = generate_captcha()
                    else:
                        st.error(message)

            if st.button(
                "🔄 Refresh CAPTCHA", key="refresh_register_captcha", use_container_width=True
            ):
                st.session_state["register_captcha"] = generate_captcha()
                st.rerun()

        st.markdown(
            "<p style='text-align:center;color:#64748b;font-size:12px;'>"
            "🛡️ Your account is protected with secure authentication</p>",
            unsafe_allow_html=True,
        )


# ---------------- LOAD AI MODEL ----------------

@st.cache_resource
def load_model():
    if not MODEL.exists():
        raise FileNotFoundError("Model missing. Run python train_model.py first.")
    return joblib.load(MODEL)


# ---------------- PHISHING DETECTION ----------------

SUSPICIOUS_TERMS = [
    "urgent", "verify", "password", "otp", "suspended", "blocked", "claim",
    "prize", "gift card", "click here", "bank details", "credit card", "kyc",
    "immediately", "final warning", "confirm your identity",
]


def inspect_email(text):
    low = text.lower()
    found = sorted({term for term in SUSPICIOUS_TERMS if term in low})
    urls = re.findall(r"https?://\S+|www\.\S+", text, flags=re.I)

    score = min(len(found) * 8, 48)
    score += min(len(urls) * 12, 24)

    if re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}", text, re.I):
        score += 20
    if re.search(r"\b(password|otp|credit card|bank details)\b", low):
        score += 15
    if re.search(r"\b(urgent|immediately|final warning)\b", low):
        score += 10

    return min(score, 100), found, urls


# ---------------- MAIN DASHBOARD ----------------

def show_dashboard():
    header_col, logout_col = st.columns([4, 1])
    with header_col:
        st.title("🛡️ SecureMail AI")
        st.caption(f"Signed in as {st.session_state.get('user_email', '')}")
    with logout_col:
        if st.button("Logout", use_container_width=True):
            st.session_state["authenticated"] = False
            st.session_state.pop("user_email", None)
            st.rerun()

    st.write("Paste an email to estimate whether it may be phishing or legitimate.")
    st.info(
        "Educational prototype only. Do not paste real passwords, OTPs, or confidential information."
    )

    try:
        model = load_model()
    except Exception as error:
        st.error(str(error))
        st.code("python train_model.py")
        st.stop()

    message = st.text_area(
        "Email Subject and Body",
        height=220,
        placeholder="Paste email text here...",
    )

    if st.button("Analyse Email", type="primary"):
        if len(message.strip()) < 15:
            st.warning("Enter a longer email message.")
        else:
            try:
                pred = str(model.predict([message])[0]).lower()
                probs = model.predict_proba([message])[0]
                classes = [str(label).lower() for label in model.classes_]
                phishing_index = classes.index("phishing") if "phishing" in classes else None
                phishing_prob = float(probs[phishing_index]) if phishing_index is not None else 0.0
            except Exception as error:
                st.error(f"Could not analyse this email: {error}")
                st.stop()

            rule_score, found, urls = inspect_email(message)
            score = round(phishing_prob * 70 + rule_score * 0.30)
            risk = pred == "phishing" or score >= 55

            # Save using the currently logged-in account email.
            save_scan(st.session_state.get("user_email", "Unknown"), pred, score)

            st.subheader("Result")
            if risk:
                st.error("⚠️ Potential phishing email")
            else:
                st.success("✅ Likely legitimate email")

            metric_a, metric_b, metric_c = st.columns(3)
            metric_a.metric("Threat Score", f"{score}/100")
            metric_b.metric("ML Phishing Score", f"{phishing_prob:.0%}")
            metric_c.metric("Links Detected", len(urls))
            st.progress(score / 100)
            st.caption("Threat score is an educational estimate, not a calibrated probability.")

            with st.expander("Why did the system produce this result?", expanded=True):
                st.write("**ML Prediction:**", pred.title())
                st.write("**Risk Terms:**", ", ".join(found) if found else "None found")
                st.write("**URLs detected:**")
                if urls:
                    for url in urls:
                        st.code(url)
                else:
                    st.write("No URLs detected.")
                st.write("The model uses TF-IDF text features and Logistic Regression.")

            if risk:
                st.warning(
                    "Do not click links, open unexpected attachments, or share passwords/OTPs. "
                    "Verify requests independently."
                )
            else:
                st.info("A legitimate-looking result does not guarantee safety.")

    # Security analytics dashboard
    st.divider()
    st.header("📊 Security Analytics Dashboard")
    analytics = get_analytics()
    phishing_count = analytics.get("phishing", 0)
    legitimate_count = analytics.get("legitimate", 0)
    total_scans = phishing_count + legitimate_count

    metric1, metric2, metric3 = st.columns(3)
    metric1.metric("Total Emails Scanned", total_scans)
    metric2.metric("Phishing Detected", phishing_count)
    metric3.metric("Legitimate Emails", legitimate_count)

    if total_scans > 0:
        phishing_percentage = (phishing_count / total_scans) * 100
        st.metric("Phishing Detection Percentage", f"{phishing_percentage:.1f}%")
        chart_data = pd.DataFrame(
            {"Email Type": ["Phishing", "Legitimate"],
             "Count": [phishing_count, legitimate_count]}
        )
        fig = px.pie(
            chart_data, names="Email Type", values="Count",
            title="Email Threat Distribution", hole=0.4
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Analyse some emails to view analytics.")

    # Scan history
    st.divider()
    st.subheader("📜 Email Scan History")
    history_records = get_history()
    if history_records:
        for record in history_records:
            st.write("Prediction:", record[2])
            st.write("Threat Score:", record[3])
            st.write("Date:", record[4])
            st.divider()
    else:
        st.info("No scan history available.")

    st.caption(
        "Demo model trained on a small sample dataset. Not suitable for real-world security decisions."
    )


# ---------------- APPLICATION ENTRY ----------------

if st.session_state.get("authenticated", False):
    show_dashboard()
else:
    show_authentication()
