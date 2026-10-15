
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
from scipy.sparse import hstack

ROOT = Path(__file__).resolve().parent
MODEL = joblib.load(ROOT / "models" / "phishing_url_model_v3.joblib")
VECTORIZER = joblib.load(ROOT / "models" / "phishing_url_vectorizer_v3.joblib")

URLS = [
    "https://www.google.com/",
    "https://www.youtube.com/",
    "https://www.wikipedia.org/",
    "https://www.microsoft.com/",
    "https://www.cloudflare.com/",
    "https://www.apple.com/",
    "https://www.python.org/",
    "https://www.mozilla.org/",
    "https://www.github.com/",
    "https://www.nhs.uk/",
]


def extract_url_features(url):
    parsed = urlparse(url)
    domain, path, query = parsed.netloc, parsed.path, parsed.query
    return [
        len(url), len(domain), len(path), len(query),
        domain.count("."), domain.count("-"), domain.count("_"),
        url.count("/"), url.count("?"), url.count("="), url.count("&"),
        url.count("%"), sum(c.isdigit() for c in url),
        sum(c.isalpha() for c in url),
        int(url.startswith("https://")), int(url.startswith("http://")),
        int("@" in url), int("://" in url), len(set(domain)),
    ]


text = VECTORIZER.transform(URLS)
structural = np.array([extract_url_features(u) for u in URLS])
features = hstack([text, structural])

predictions = MODEL.predict(features)
probabilities = MODEL.predict_proba(features)

print("Model classes:", MODEL.classes_)
print("\nPredictions (labels are not yet verified):")
for url, pred, probs in zip(URLS, predictions, probabilities):
    confidence = max(probs) * 100
    print(f"Label {pred} | confidence {confidence:.1f}% | {url}")
