
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack
from datasets import load_dataset
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent

model = joblib.load(ROOT / "models" / "phishing_url_model_v3.joblib")
vectorizer = joblib.load(ROOT / "models" / "phishing_url_vectorizer_v3.joblib")

# Use the dataset's separate validation split.
dataset = load_dataset("kmack/Phishing_urls", split="valid")
df = dataset.to_pandas()

def extract_url_features(url):
    url = str(url)
    parsed = urlparse(url)
    domain, path, query = parsed.netloc, parsed.path, parsed.query

    return [
        len(url), len(domain), len(path), len(query),
        domain.count("."), domain.count("-"), domain.count("_"),
        url.count("/"), url.count("?"), url.count("="),
        url.count("&"), url.count("%"),
        sum(c.isdigit() for c in url),
        sum(c.isalpha() for c in url),
        int(url.startswith("https://")),
        int(url.startswith("http://")),
        int("@" in url), int("://" in url), len(set(domain)),
    ]

urls = df["text"].fillna("").astype(str).tolist()
y_true = df["label"].astype(int).to_numpy()

text_features = vectorizer.transform(urls)
url_features = np.array([extract_url_features(u) for u in urls])
X = hstack([text_features, url_features])

y_pred = model.predict(X)

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

print("Model classes:", model.classes_)
print("Validation accuracy:", round(accuracy_score(y_true, y_pred), 4))
print("Confusion matrix (rows=true, columns=predicted; labels 0, 1):")
print(confusion_matrix(y_true, y_pred, labels=[0, 1]))
print(classification_report(y_true, y_pred, labels=[0, 1], zero_division=0))
