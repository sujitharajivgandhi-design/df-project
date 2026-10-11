import os
import sys
import joblib
import pandas as pd
from urllib.parse import urlparse

# ============================================================
# AI-BASED BROWSER PHISHING ANALYSIS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

MODEL_PATH = os.path.join(PROJECT_DIR, "models", "phishing_model.pkl")
SCALER_PATH = os.path.join(PROJECT_DIR, "models", "scaler.pkl")
HISTORY_PATH = os.path.join(BASE_DIR, "history.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "suspicious_urls_v3.csv")

# These names and their order must match the model's training pipeline.
FEATURES = [
    "url_length",
    "valid_url",
    "at_symbol",
    "sensitive_words_count",
    "path_length",
    "isHttps",
    "nb_dots",
    "nb_hyphens",
    "nb_and",
    "nb_or",
    "nb_www",
    "nb_com",
    "nb_underscore",
]

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account",
    "password", "signin", "banking", "confirm", "wallet",
    "payment", "authenticate", "suspend",
]


def extract_features(url):
    """Extract URL features. This must match the training procedure."""
    url = str(url).strip()
    lower_url = url.lower()
    parsed = urlparse(url if "://" in url else "//" + url)
    hostname = parsed.hostname or ""

    return {
        "url_length": len(url),
        "valid_url": int(bool(hostname and "." in hostname)),
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


def identify_phishing_class(model):
    """Identify the phishing label using common explicit class names."""
    if not hasattr(model, "classes_"):
        raise ValueError("The loaded model does not expose classes_.")

    classes = list(model.classes_)
    supported_labels = {"1", "phishing", "malicious", "unsafe"}

    for label in classes:
        if str(label).strip().lower() in supported_labels:
            return label

    raise ValueError(
        f"Cannot identify the phishing class from model classes {classes}. "
        "Check the target labels used during training."
    )


def is_web_url(value):
    """Accept only URLs with a valid HTTP or HTTPS scheme and hostname."""
    try:
        parsed = urlparse(str(value).strip())
        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
        )
    except (TypeError, ValueError):
        return False


def main():
    print("=" * 60)
    print("AI-BASED BROWSER PHISHING ANALYSIS")
    print("=" * 60)

    for path in (MODEL_PATH, SCALER_PATH, HISTORY_PATH):
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Required file not found: {path}")

    print("\nLoading model and scaler...")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    model_feature_count = getattr(model, "n_features_in_", None)
    scaler_feature_count = getattr(scaler, "n_features_in_", None)

    if model_feature_count is not None and model_feature_count != len(FEATURES):
        raise ValueError(
            f"Model expects {model_feature_count} features; "
            f"this script supplies {len(FEATURES)}."
        )

    if scaler_feature_count is not None and scaler_feature_count != len(FEATURES):
        raise ValueError(
            f"Scaler expects {scaler_feature_count} features; "
            f"this script supplies {len(FEATURES)}."
        )

    if not callable(getattr(scaler, "transform", None)):
        raise ValueError("The loaded scaler does not support transform().")

    if not callable(getattr(model, "predict", None)):
        raise ValueError("The loaded model does not support predict().")

    if not callable(getattr(model, "predict_proba", None)):
        raise ValueError(
            "The loaded model does not support predict_proba()."
        )

    phishing_class = identify_phishing_class(model)
    classes = list(model.classes_)
    phishing_index = classes.index(phishing_class)

    print(f"Model classes: {classes}")
    print(f"Phishing class assumed from labels: {phishing_class}")

    print("\nReading browser history...")
    history = pd.read_csv(HISTORY_PATH)

    if "URL" not in history.columns:
        raise ValueError(
            "history.csv must contain a 'URL' column. "
            f"Found columns: {history.columns.tolist()}"
        )

    original_count = len(history)
    history = history.dropna(subset=["URL"]).copy()
    history["URL"] = history["URL"].astype(str).str.strip()
    history = history[history["URL"].ne("")].copy()
    history = history[history["URL"].apply(is_web_url)].copy()

    if history.empty:
        raise ValueError("No valid HTTP/HTTPS URLs found in history.csv.")

    unique_urls = history["URL"].drop_duplicates().tolist()

    print(f"History rows loaded: {original_count}")
    print(f"Valid HTTP/HTTPS history rows: {len(history)}")
    print(f"Unique URLs to analyze: {len(unique_urls)}")

    print("\nExtracting features...")
    feature_df = pd.DataFrame(
        [extract_features(url) for url in unique_urls],
        columns=FEATURES,
    )

    if feature_df.isnull().any().any():
        raise ValueError("Feature extraction produced missing values.")

    print("Scaling features...")
    scaled_features = scaler.transform(feature_df)

    print("Predicting URL classifications...")
    predictions = model.predict(scaled_features)
    probabilities = model.predict_proba(scaled_features)

    if len(predictions) != len(unique_urls):
        raise ValueError("Unexpected number of model predictions.")

    if probabilities.shape[1] != len(classes):
        raise ValueError("Probability columns do not match model classes.")

    results = []

    for url, prediction, probs in zip(unique_urls, predictions, probabilities):
        matching = history[history["URL"] == url]

        browser_names = (
            matching["Browser"].dropna().astype(str).unique().tolist()
            if "Browser" in matching.columns else []
        )
        visit_times = (
            matching["Visit Time"].dropna().astype(str).tolist()
            if "Visit Time" in matching.columns else []
        )

        predicted_index = classes.index(prediction)
        status = "PHISHING" if prediction == phishing_class else "BENIGN"

        results.append({
            "Browser": ", ".join(browser_names) if browser_names else "Unknown",
            "URL": url,
            "Status": status,
            "Confidence": round(float(probs[predicted_index]) * 100, 2),
            "Phishing Probability": round(float(probs[phishing_index]) * 100, 2),
            "Visit Time": visit_times[0] if visit_times else "",
        })

    result_df = pd.DataFrame(results)
    result_df.to_csv(OUTPUT_PATH, index=False, encoding="utf-8")

    phishing_count = int((result_df["Status"] == "PHISHING").sum())
    benign_count = int((result_df["Status"] == "BENIGN").sum())

    print("\n" + "=" * 60)
    print("BROWSER AI ANALYSIS COMPLETED")
    print("=" * 60)
    print(f"URLs analyzed: {len(result_df)}")
    print(f"Potential phishing URLs: {phishing_count}")
    print(f"URLs classified as benign: {benign_count}")
    print(f"Results saved to: {OUTPUT_PATH}")
    print("Note: Predictions are estimates, not proof that a URL is malicious or safe.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("\nAI PHISHING ANALYSIS FAILED")
        print(f"{type(error).__name__}: {error}")
        sys.exit(1)
