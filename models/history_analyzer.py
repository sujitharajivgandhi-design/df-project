
import os
import joblib
import pandas as pd
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")

FEATURES = [
    "url_length", "valid_url", "at_symbol",
    "sensitive_words_count", "path_length", "isHttps",
    "nb_dots", "nb_hyphens", "nb_and", "nb_or",
    "nb_www", "nb_com", "nb_underscore",
]

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account",
    "password", "signin", "banking", "confirm", "wallet",
    "payment", "authenticate", "suspend",
]

def extract_features(url):
    url = str(url).strip()
    lower_url = url.lower()
    parsed = urlparse(url if "://" in url else "//" + url)
    domain = parsed.netloc.split("@")[-1].split(":")[0]

    return {
        "url_length": len(url),
        "valid_url": int(bool(domain and "." in domain)),
        "at_symbol": int("@" in url),
        "sensitive_words_count": sum(
            lower_url.count(word) for word in SUSPICIOUS_WORDS
        ),
        "path_length": len(parsed.path),
        "isHttps": int(lower_url.startswith("https://")),
        "nb_dots": lower_url.count("."),
        "nb_hyphens": lower_url.count("-"),
        "nb_and": lower_url.count("and"),
        "nb_or": lower_url.count("or"),
        "nb_www": lower_url.count("www"),
        "nb_com": lower_url.count(".com"),
        "nb_underscore": lower_url.count("_"),
    }

def analyze_history(records):
    if not records:
        return []

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    classes = list(model.classes_)
    phishing_class = next(
        (
            c for c in classes
            if str(c).strip().lower()
            in {"1", "phishing", "malicious", "unsafe"}
        ),
        None,
    )

    if phishing_class is None:
        raise ValueError(
            f"Cannot identify phishing label from model classes: {classes}"
        )

    frame = pd.DataFrame(records)
    if "url" not in frame.columns:
        raise ValueError("History records must contain 'url'.")

    frame = frame.dropna(subset=["url"]).copy()
    frame["url"] = frame["url"].astype(str).str.strip()
    frame = frame[
        frame["url"].str.startswith(("http://", "https://"))
        & (frame["url"] != "")
    ]

    if frame.empty:
        return []

    unique_urls = frame["url"].drop_duplicates().tolist()
    feature_df = pd.DataFrame(
        [extract_features(url) for url in unique_urls],
        columns=FEATURES,
    )

    scaled = scaler.transform(feature_df)
    predictions = model.predict(scaled)
    probabilities = model.predict_proba(scaled)
    phishing_index = classes.index(phishing_class)

    result_by_url = {}
    for url, prediction, probs in zip(
        unique_urls, predictions, probabilities
    ):
        predicted_index = classes.index(prediction)
        result_by_url[url] = {
            "status": (
                "PHISHING" if prediction == phishing_class else "BENIGN"
            ),
            "confidence": round(
                float(probs[predicted_index]) * 100, 2
            ),
            "phishing_probability": round(
                float(probs[phishing_index]) * 100, 2
            ),
        }

    return [
        {**record, **result_by_url[record["url"]]}
        for record in frame.to_dict(orient="records")
    ]
