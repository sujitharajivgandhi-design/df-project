
from models.history_analyzer_v3 import analyze_history_v3

sample_records = [
    {"url": "https://www.google.com/", "title": "Google"},
    {"url": "https://www.youtube.com/", "title": "YouTube"},
    {"url": "https://www.microsoft.com/", "title": "Microsoft"},
]

for result in analyze_history_v3(sample_records):
    print(result)
