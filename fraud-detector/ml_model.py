import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import re

# Feature extraction function
def extract_features(url):

    return [
        len(url),                 # URL length
        url.count("-"),           # hyphen count
        url.count("."),           # dot count
        int("https" in url),      # HTTPS usage
        int(re.search(r'\d+\.\d+\.\d+\.\d+', url) is not None)  # IP address
    ]


# Load dataset
data = pd.read_csv("data/url_dataset.csv")

X = []
y = []

for url, label in zip(data["url"], data["label"]):

    features = extract_features(url)

    X.append(features)
    y.append(label)


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = RandomForestClassifier()

model.fit(X_train, y_train)

# Save trained model
joblib.dump(model, "phishing_model.pkl")

print("Model trained and saved.")