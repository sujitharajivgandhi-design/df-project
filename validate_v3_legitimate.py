
from models.history_analyzer_v3 import analyze_history_v3

# These are known legitimate websites.
# This checks predictions, not confirmed phishing probabilities.
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

records = [
    {"url": url, "title": "Legitimate-site validation"}
    for url in urls
]

results = analyze_history_v3(records)

print("\nV3 LEGITIMATE WEBSITE VALIDATION")
print("-" * 60)

class_1_count = 0

for result in results:
    probabilities = result["class_probabilities"]
    predicted = result["predicted_label"]

    if predicted == 1:
        class_1_count += 1

    print(f"URL: {result['url']}")
    print(f"Predicted class: {predicted}")
    print(f"Class 0 score: {probabilities['0']}%")
    print(f"Class 1 score: {probabilities['1']}%")
    print("-" * 60)

print(f"Total tested: {len(results)}")
print(f"Predicted class 1: {class_1_count}")
print(f"Predicted class 0: {len(results) - class_1_count}")
print("Reminder: class meanings are not yet verified.")
