# AI-Powered Email Threat Detection System

## 1. Project Overview

**Project name:** SecureMail AI

**Purpose:** Provide an educational email-analysis application that combines machine-learning classification with rule-based indicators to estimate whether an email is phishing or legitimate.

**Technology stack:**

| Component | Technology |
|---|---|
| User interface | Streamlit |
| Programming language | Python |
| Text processing | scikit-learn TF-IDF |
| Classification | Logistic Regression |
| Data processing | Pandas |
| Visualization | Plotly |
| Authentication and history | SQLite |
| Model serialization | Joblib |

**Repository entry points:**

- [app.py](app.py) - Streamlit interface, authentication, detection, and dashboard
- [train_model.py](train_model.py) - Training pipeline and model generation
- [history.py](history.py) - SQLite scan-history operations
- [data/emails.csv](data/emails.csv) - Training dataset
- [models/email_detector.joblib](models/email_detector.joblib) - Serialized trained model
- [users.db](users.db) - Local authentication and scan-history database

## 2. System Goals

The project aims to:

1. Authenticate users securely.
2. Analyse pasted email subject and body text.
3. Estimate whether an email is phishing or legitimate.
4. Identify suspicious words and URL patterns.
5. Present an interpretable threat score.
6. Store scan history and security analytics.

This is a prototype and is not a substitute for an enterprise email-security gateway or human security review.

## 3. Dataset

The training data contains 50 records after removing empty rows:

- 30 legitimate emails
- 20 phishing emails

The data represents short, obvious examples of email content. It includes phishing patterns such as urgency, credential requests, payment demands, prize claims, account suspension warnings, and suspicious links.

**Dataset limitations:**

- The dataset is small.
- It may not represent modern phishing campaigns.
- Some examples are highly repetitive or template-like.
- A random 25% test split is limited to 13 samples.
- The 100% measured test accuracy is therefore not evidence of production-grade performance.

## 4. System Architecture

```text
User
  |
  v
Streamlit authentication page
  |
  +--> SQLite users table
  |
  v
Authenticated dashboard
  |
  +--> Email text
  |      |
  |      +--> TF-IDF and Logistic Regression
  |      |
  |      +--> Keyword and URL rules
  |             |
  |             v
  |       Combined threat score
  |
  v
SQLite scan_history table
  |
  v
Scan history and analytics dashboard
```

## 5. Authentication Design

The application supports registration, login, logout, and CAPTCHA verification.

### Registration

1. Validate the email format.
2. Require a password of at least eight characters.
3. Require password confirmation.
4. Verify the mathematical CAPTCHA.
5. Generate a random 16-byte salt.
6. Hash the password using PBKDF2-HMAC-SHA256.
7. Store the email, salt, and hash in SQLite.

The password is not stored in plaintext.

### Login

1. Normalize and look up the email address.
2. Retrieve the account's stored salt and hash.
3. Recalculate the password hash.
4. Compare hashes using constant-time `hmac.compare_digest`.
5. Store authentication and email identity in Streamlit session state.

### Database tables

The `users` table contains:

- `id`
- `email`
- `salt`
- `password_hash`

The `scan_history` table contains:

- `id`
- `email`
- `prediction`
- `threat_score`
- `scan_date`

## 6. Machine-Learning Pipeline

The training script creates a scikit-learn pipeline:

```text
Email text
  -> TF-IDF Vectorizer
  -> Logistic Regression
  -> Phishing or Legitimate
```

### TF-IDF configuration

- Uses unigrams and bigrams.
- Converts text to lowercase.
- Removes English stop words.
- Converts text into sparse numeric features.

### Logistic Regression configuration

- Maximum iterations: 1000
- Class weighting: balanced
- Test data: 25%
- Random seed: 42
- Stratified train/test splitting

The trained pipeline is serialized to `models/email_detector.joblib`.

## 7. Email Prediction Workflow

After the user submits an email:

1. The text must contain at least 15 characters.
2. The model is loaded through Streamlit's resource cache.
3. `predict()` returns the model's text label.
4. `predict_proba()` returns class probabilities.
5. The probability for the phishing class is identified.
6. Rule-based inspection calculates a separate rule score.
7. A final threat score is calculated.
8. The result is stored in scan history.

The threat score is:

```python
score = round(phishing_probability * 70 + rule_score * 0.30)
```

The final score is constrained to the range 0-100.

An email is marked risky when it is predicted as phishing or when the combined score reaches 55 or more.

## 8. Rule-Based Inspection

The rule engine identifies:

- Urgent or immediate-action language
- Password and OTP requests
- Banking and credit-card details
- Account suspension or blocking claims
- Prize and gift-card claims
- Requests to click links
- KYC requests
- HTTP/HTTPS URLs
- Numeric-IP URLs

The rule score includes:

- Up to 48 points for matched suspicious terms
- Up to 24 points for detected URLs
- 20 points for numeric-IP URLs
- 15 points for credential or banking terms
- 10 points for urgency terms

The score is capped at 100.

This layer makes the result easier to explain, but the fixed keywords and weights can produce false positives or false negatives.

## 9. Scan History and Analytics

For every analysis, `history.py` stores:

- Logged-in account email
- Prediction
- Threat score
- Scan date and time

The dashboard calculates:

- Total scans
- Phishing count
- Legitimate count
- Phishing percentage
- Email-threat distribution chart
- Previous scan records

The current history and analytics functions retrieve all records, not records belonging only to the signed-in user.

## 10. Model Evaluation

A training run in the project environment produced:

| Metric | Legitimate | Phishing |
|---|---:|---:|
| Precision | 1.00 | 1.00 |
| Recall | 1.00 | 1.00 |
| F1-score | 1.00 | 1.00 |

- Test accuracy: 100%
- Test samples: 13
- Legitimate test samples: 8
- Phishing test samples: 5

The perfect score should be reported cautiously. It was obtained using a small, simplistic, homogeneous dataset and 25% hold-out test split. No external or real-world email dataset was evaluated.

## 11. Strengths

- Complete end-to-end prototype.
- Interactive Streamlit interface.
- Combined ML and rule-based analysis.
- Password hashing with an individual random salt.
- Persistent account and scan data.
- Cached model loading.
- Clear explanatory UI for detected terms and URLs.
- Persistent analytics and scan history.

## 12. Limitations and Security Risks

### Model limitations

- Very small dataset.
- Poor coverage of modern phishing techniques.
- High risk of data leakage if sample language is reused between sets.
- Cannot inspect attachments or email headers.
- Cannot verify domains or inspect malicious URL destinations.
- Does not detect business-email compromise based on sender reputation or context.

### Application limitations

- CAPTCHA is simple arithmetic and is not anti-bot protection.
- Session authentication is suitable only for a local prototype.
- The application does not implement password reset or account recovery.
- Scan history is not currently user-filtered.
- Database records may expose personal email addresses.
- No role-based access control or administrator controls exist.
- The app uses a local SQLite database, not a managed multi-user database.
- The threat score is an estimate, not a calibrated probability.

### Security recommendations

1. Add server-side session security and secure session secret configuration.
2. Filter history and analytics by the authenticated account.
3. Add rate limiting and stronger anti-automation controls.
4. Move authentication and threat data to a secure backend database.
5. Add HTTPS and environment-based secrets when deployed.
6. Avoid storing raw email content for unnecessarily long periods.
7. Expand the dataset significantly using representative, validated sources.
8. Use cross-validation and a separate external test dataset.
9. Report precision, recall, false-positive rate, and false-negative rate.
10. Add URL reputation, domain, DNS, and redirection analysis.
11. Add authentication headers analysis, attachment scanning, and URL sandboxing.
12. Use the score only as a warning mechanism, never as the sole decision authority.

## 13. Recommended Future Work

1. Create a larger and more realistic multilingual dataset.
2. Split data by campaign or organization to avoid duplicate examples across sets.
3. Add explainable feature weights or SHAP-based explanations.
4. Analyse email headers and domains.
5. Implement link rewriting and destination inspection.
6. Add attachment and macro scanning.
7. Generate downloadable PDF or JSON reports.
8. Add an administrator audit dashboard.
9. Add account isolation and authorization tests.
10. Add automated unit and integration tests.
11. Add CI/CD model-quality gates.

## 14. Conclusion

SecureMail AI demonstrates a complete educational workflow: account registration, authenticated access, text preprocessing, ML classification, rule-based risk analysis, scan storage, and dashboard reporting.

The project is technically functional and suitable for demonstration or coursework. However, its small dataset and simplistic rule engine limit real-world reliability. The system should be described as an educational prototype, and the stated 100% test accuracy should not be presented as production performance.
