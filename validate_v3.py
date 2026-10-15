
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
from scipy.sparse import hstack

ROOT = Path(__file__).resolve().parent

model = joblib.load(ROOT / "models" / "phishing_url_model_v3.joblib")
vectorizer = joblib.load(ROOT / "models" / "phishing_url_vectorizer_v3.joblib")

# These are test examples, not a complete validation dataset.
urls = [
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
        url.count("/"), url.count("?"), url.count("="),
        url.count("&"), url.count("%"),
        sum(c.isdigit() for c in url),
        sum(c.isalpha() for c in url),
        int(url.startswith("https://")),
        int(url.startswith("http://")),
        int("@" in url), int("://" in url), len(set(domain)),
    ]

text_features = vectorizer.transform(urls)
url_features = np.array([extract_url_features(u) for u in urls])
combined_features = hstack([text_features, url_features])

predictions = model.predict(combined_features)
probabilities = model.predict_proba(combined_features)

print("Model classes:", model.classes_)
print("\nPredictions (labels not yet verified):")

for url, prediction, probs in zip(urls, predictions, probabilities):
    scores = ", ".join(
        f"class {label}: {prob * 100:.1f}%"
        for label, prob in zip(model.classes_, probs)
    )
    print(f"Predicted class {prediction} | {scores} | {url}")
