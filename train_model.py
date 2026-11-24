from pathlib import Path
import joblib
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

ROOT = Path(__file__).resolve().parent
df = pd.read_csv(ROOT / "data" / "emails.csv").dropna()
X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.25, random_state=42, stratify=df["label"]
)
model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, stop_words="english")),
    ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced"))
])
model.fit(X_train, y_train)
pred = model.predict(X_test)
print("Demo test accuracy:", f"{accuracy_score(y_test, pred):.1%}")
print(classification_report(y_test, pred))
out = ROOT / "models"
out.mkdir(exist_ok=True)
joblib.dump(model, out / "email_detector.joblib")
print("Model saved in models/email_detector.joblib")
