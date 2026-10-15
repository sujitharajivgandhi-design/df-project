
from pathlib import Path
import sys
import warnings

import joblib
import pandas as pd
from sklearn.exceptions import InconsistentVersionWarning

warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from models.history_analyzer import FEATURES, extract_features

model = joblib.load(PROJECT_ROOT / "models" / "phishing_model.pkl")
scaler = joblib.load(PROJECT_ROOT / "models" / "scaler.pkl")

benign_path = PROJECT_ROOT / "dataset" / "benign_urls.csv"
benign = pd.read_csv(benign_path)

urls = (
    benign.loc[benign["label"] == 0, "text"]
    .dropna()
    .astype(str)
    .head(20)
)

features = pd.DataFrame(
    [extract_features(url) for url in urls],
    columns=FEATURES,
)

scaled_features = scaler.transform(features)
predictions = model.predict(scaled_features)

print("Classes:", list(model.classes_))
print("Benign URLs tested:", len(urls))
print("Predictions:", pd.Series(predictions).value_counts().to_dict())
print("\nIndividual results:")

for url, prediction in zip(urls, predictions):
    print(f"Class {prediction}: {url}")
