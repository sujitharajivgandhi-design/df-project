
import joblib
from pathlib import Path
import pandas as pd

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from models.history_analyzer import extract_features, FEATURES

BASE_DIR = PROJECT_ROOT
model = joblib.load(BASE_DIR / "models" / "phishing_model.pkl")
scaler = joblib.load(BASE_DIR / "models" / "scaler.pkl")

print("Model classes:", model.classes_)
print("Model type:", type(model).__name__)
print("Model expected features:", getattr(model, "n_features_in_", "unknown"))
print("Scaler expected features:", getattr(scaler, "n_features_in_", "unknown"))
print("Analyzer feature count:", len(FEATURES))

urls = [
    "https://www.youtube.com/",
    "https://www.google.com/",
    "https://example.com/",
    "http://example.com/login",
]

features = pd.DataFrame(
    [extract_features(url) for url in urls],
    columns=FEATURES,
)

scaled = scaler.transform(features)
predictions = model.predict(scaled)
probabilities = model.predict_proba(scaled)

for url, prediction, probs in zip(urls, predictions, probabilities):
    print("\nURL:", url)
    print("Raw prediction:", prediction)
    print(
        "Probabilities:",
        dict(zip(model.classes_, probs.round(4))),
    )
