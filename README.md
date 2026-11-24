# 🛡️ AI-Powered Email Threat Detection System

An AI-based web application that detects potentially phishing and legitimate emails using Machine Learning. The system provides email threat analysis, secure user authentication, scan history, and security analytics through an interactive Streamlit dashboard.

## 🚀 Features

### 1. User Authentication
- User registration and login.
- Mathematical CAPTCHA verification.
- Password hashing for secure password storage.
- Logout functionality.

### 2. AI Email Threat Detection
- Classifies emails as Phishing or Legitimate.
- Uses TF-IDF for text feature extraction.
- Uses Logistic Regression for classification.
- Calculates an estimated threat score.
- Identifies suspicious keywords.

### 3. Suspicious URL Detection
- Extracts URLs from email content.
- Identifies suspicious URL patterns.
- Displays detected links for manual inspection.

### 4. Email Scan History
- Stores email scan records in SQLite.
- Displays previous predictions.
- Shows threat scores and scan dates.

### 5. Security Analytics Dashboard
- Displays total emails scanned.
- Counts phishing and legitimate emails.
- Calculates phishing detection percentage.
- Visualizes email threat distribution using a pie chart.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Programming language |
| Streamlit | Web application interface |
| Scikit-learn | Machine Learning |
| Pandas | Data processing |
| Plotly | Data visualization |
| SQLite | Database |
| TF-IDF | Text feature extraction |
| Logistic Regression | Email classification |
| Joblib | Model storage |

## 📁 Project Structure

```text
AI_Email_Threat_Detection/
│
├── app.py
├── train_model.py
├── history.py
├── requirements.txt
├── README.md
│
├── data/
│   └── emails.csv
│
├── models/
│   └── email_detector.joblib
│
└── users.db
```

`users.db` is generated locally when the application runs and should not be uploaded to GitHub.

## ⚙️ Installation and Setup

### Step 1: Clone the repository

```bash
git clone https://github.com/savitasajjan2005-maker/savita-.git
```

### Step 2: Open the project folder

```bash
cd savita-
```

### Step 3: Create a virtual environment

```bash
python -m venv .venv
```

### Step 4: Activate the virtual environment

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### Step 5: Install dependencies

```bash
python -m pip install -r requirements.txt
```

### Step 6: Train the Machine Learning model

```bash
python train_model.py
```

### Step 7: Run the application

```bash
python -m streamlit run app.py
```

The application will open in your browser.

## 📊 How It Works

1. The user registers or logs in using the authentication page.
2. The user enters an email subject and message.
3. The application extracts text features using TF-IDF.
4. The trained Logistic Regression model predicts the email category.
5. The system calculates an estimated threat score.
6. Suspicious keywords and URLs are identified.
7. Scan results are stored in the SQLite database.
8. The analytics dashboard displays email security statistics.

## 🔮 Future Enhancements

- Explainable AI for better prediction transparency.
- Advanced malicious URL analysis.
- Email attachment scanning.
- PDF security report generation.
- Admin dashboard and user management.
- Improved phishing detection using larger datasets.

## ⚠️ Disclaimer

This project is an educational Machine Learning prototype. Its predictions and threat scores are estimates and are not guaranteed to identify all phishing attacks. Do not use it as the sole method of real-world email security.

## 👩‍💻 Project Information

**Project:** AI-Powered Email Threat Detection System  
**Domain:** Artificial Intelligence and Machine Learning  
**Interface:** Streamlit  
**Language:** Python