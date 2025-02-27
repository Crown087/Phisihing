# Import required libraries
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
import joblib
import re

# Step 1: Load the Dataset
file_path = 'phishing_data(Sheet1).csv'  # Update this to the actual file path
data = pd.read_csv(file_path)

# Display dataset overview
print("Dataset Overview:")
print(data.head())

# Step 2: Feature Extraction from URLs
def extract_features_from_url(url):
    """Extract features from a URL for phishing detection."""
    features = []
    features.append(len(url))                               # Feature: Length of URL
    features.append(int('@' in url))                       # Feature: Presence of '@'
    features.append(int('-' in url))                       # Feature: Presence of '-'
    features.append(int(url.startswith('https')))          # Feature: Presence of HTTPS
    features.append(int(re.search(r'\d+', url) is not None))  # Feature: Digits in URL
    features.append(int('.' in url.split('/')[0]))          # Feature: Subdomains
    return features

# Apply feature extraction
data['features'] = data['URLs'].apply(extract_features_from_url)

# Convert features column into a DataFrame
features_df = pd.DataFrame(data['features'].tolist(), columns=[
    'url_length', 'has_at', 'has_dash', 'https', 'has_digits', 'subdomains'
])

# Combine features and labels
X = features_df
y = data['Labels']

# Step 3: Split the Dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Normalize the features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Step 4: Train a Machine Learning Model
model = RandomForestClassifier(random_state=42)
model.fit(X_train_scaled, y_train)

# Step 5: Evaluate the Model
y_pred = model.predict(X_test_scaled)

# Display evaluation metrics
print("\nModel Performance:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Step 6: Save the Trained Model
joblib.dump(model, 'phishing_website_detector.pkl')
joblib.dump(scaler, 'scaler.pkl')  # Save the scaler for consistent preprocessing
print("\nModel saved as 'phishing_website_detector.pkl' and scaler as 'scaler.pkl'.")

# Step 7: Backend Logic for User Input
def predict_website_legitimacy(url):
    """Predict if a website is phishing or legitimate."""
    # Load the trained model and scaler
    model = joblib.load('phishing_website_detector.pkl')
    scaler = joblib.load('scaler.pkl')

    # Extract features and preprocess
    features = extract_features_from_url(url)
    features_scaled = scaler.transform([features])

    # Make prediction
    prediction = model.predict(features_scaled)[0]
    return prediction

# Example: User Input
user_url = input("\nEnter a website URL to check (e.g., https://example.com): ")
prediction = predict_website_legitimacy(user_url)

if prediction == 0:
    print(f"The website '{user_url}' is classified as a LEGITIMATE website.")
else:
    print(f"The website '{user_url}' is classified as a PHISHING website.")
