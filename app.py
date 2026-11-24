from pathlib import Path
import re
import joblib
import streamlit as st

ROOT = Path(__file__).resolve().parent
MODEL = ROOT / "models" / "email_detector.joblib"
st.set_page_config(page_title="AI Email Threat Detector", page_icon="🛡️")
st.title("🛡️ AI Email Threat Detector")
st.write("Paste an email to estimate whether it may be phishing or legitimate.")
st.info("Educational prototype only. Do not paste real passwords, OTPs, or confidential information.")

@st.cache_resource
def load_model():
    if not MODEL.exists():
        raise FileNotFoundError("Model missing. First run: python train_model.py")
    return joblib.load(MODEL)

terms = ["urgent", "verify", "password", "otp", "suspended", "blocked", "claim",
         "prize", "gift card", "click here", "bank details", "credit card", "kyc",
         "immediately", "final warning", "confirm your identity"]

def inspect(text):
    low = text.lower()
    found = sorted({t for t in terms if t in low})
    urls = re.findall(r"https?://\\S+|www\\.\\S+", text, flags=re.I)
    score = min(len(found)*8, 48) + min(len(urls)*12, 24)
    if re.search(r"https?://(?:\\d{1,3}\\.){3}\\d{1,3}", text, re.I): score += 20
    if re.search(r"\\b(password|otp|credit card|bank details)\\b", low): score += 15
    if re.search(r"\\b(urgent|immediately|final warning)\\b", low): score += 10
    return min(score, 100), found, urls

try:
    model = load_model()
except Exception as e:
    st.error(str(e))
    st.code("python train_model.py\\nstreamlit run app.py")
    st.stop()

message = st.text_area("Email subject and body", height=220, placeholder="Paste email text here...")
if st.button("Analyse email", type="primary"):
    if len(message.strip()) < 15:
        st.warning("Enter a longer email message.")
    else:
        pred = model.predict([message])[0]
        probs = model.predict_proba([message])[0]
        phishing_prob = float(probs[list(model.classes_).index("phishing")])
        rule_score, found, urls = inspect(message)
        score = round(phishing_prob*70 + rule_score*0.30)
        risk = pred == "phishing" or score >= 55

        st.subheader("Result")
        if risk: st.error("⚠️ Potential phishing email")
        else: st.success("✅ Likely legitimate email")
        a,b,c = st.columns(3)
        a.metric("Threat score", f"{score}/100")
        b.metric("ML phishing score", f"{phishing_prob:.0%}")
        c.metric("Links detected", len(urls))
        st.progress(score/100)
        st.caption("Threat score is an educational estimate, not a calibrated probability.")
        with st.expander("Why did the system produce this result?", expanded=True):
            st.write("**ML prediction:**", pred.title())
            st.write("**Risk terms:**", ", ".join(found) if found else "None of the configured terms found")
            st.write("**URLs:**")
            if urls:
                for u in urls: st.code(u)
            else: st.write("No URLs detected.")
            st.write("The model uses TF-IDF text features and Logistic Regression. The score also uses visible rule-based indicators.")
        if risk:
            st.warning("Do not click links, open unexpected attachments, or share passwords/OTPs. Verify the request using the organisation's official website or a known phone number.")
        else:
            st.info("A legitimate-looking result does not guarantee safety. Check the sender address and verify unexpected requests independently.")

st.divider()
st.caption("Demo model trained on a small sample dataset. Not suitable for real-world security decisions.")
