
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
from scipy.sparse import hstack

ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = ROOT / "models" / "phishing_url_model_v3.joblib"
VECTORIZER_PATH = ROOT / "models" / "phishing_url_vectorizer_v3.joblib"


def extract_url_features(url):
    url = str(url).strip()
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


def analyze_history_v3(records):
    if not records:
        return []

    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)

    valid_records = []
    for record in records:
        url = str(record.get("url", "")).strip()
        if url.startswith(("http://", "https://")):
            valid_records.append({**record, "url": url})

    if not valid_records:
        return []

    urls = [record["url"] for record in valid_records]

    text_features = vectorizer.transform(urls)
    url_features = np.asarray(
        [extract_url_features(url) for url in urls]
    )
    combined_features = hstack([text_features, url_features])

    predictions = model.predict(combined_features)
    probabilities = model.predict_proba(combined_features)

    results = []
    for record, prediction, probs in zip(
        valid_records, predictions, probabilities
    ):
        results.append({
            **record,
            "model_version": "v3",
            "predicted_label": int(prediction),
            "class_probabilities": {
                str(label): round(float(prob) * 100, 2)
                for label, prob in zip(model.classes_, probs)
            },
            "label_mapping_verified": False,
        })

    return results
