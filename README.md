# AI Email Threat Detection System

A small Python + Machine Learning web prototype. It classifies pasted email text as phishing or legitimate, displays an estimated threat score, and highlights suspicious phrases and links.

## Windows setup (PowerShell)

1. Extract the ZIP to Documents or Desktop, **not** `C:\Program Files`.
2. Open this folder in VS Code, then Terminal > New Terminal.
3. Create a virtual environment:
   `py -3.11 -m venv .venv`
   If Python 3.11 is unavailable, use `py -m venv .venv` with an installed compatible Python.
4. Activate:
   `.\.venv\Scripts\Activate.ps1`
   If blocked, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again.
5. Install:
   `python -m pip install --upgrade pip`
   `pip install -r requirements.txt`
6. Train:
   `python train_model.py`
7. Run:
   `streamlit run app.py`

## Demo examples

Phishing: `URGENT: Your bank account is suspended. Verify your identity immediately at http://secure-bank.example to avoid closure.`

Legitimate: `Hi team, please find the meeting agenda attached. Our meeting is scheduled for 10 AM tomorrow.`

## How it works

Email text -> TF-IDF vectorizer -> Logistic Regression classifier -> prediction and phishing score -> visible indicators in Streamlit.

## Limitations

The bundled CSV is a small teaching dataset. Results and accuracy are not representative of real email traffic. The score is not a calibrated probability. This prototype does not inspect email headers, attachments, sender reputation, redirects, or malware. Never rely on it alone for security decisions and never paste confidential messages, passwords, or OTPs.
