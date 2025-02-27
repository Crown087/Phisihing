from flask import Flask, request, jsonify, render_template_string
import joblib
import re

# Load the trained model and scaler
model = joblib.load('phishing_website_detector.pkl')
scaler = joblib.load('scaler.pkl')

# Initialize Flask app
app = Flask(__name__)

# Feature extraction function
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

# Default route to display a form with CSS
@app.route('/')
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phishing Website Detector</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f9;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }
            .container {
                text-align: center;
                background: #fff;
                padding: 20px 40px;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }
            h1 {
                color: #333;
            }
            p {
                color: #666;
            }
            form {
                display: flex;
                flex-direction: column;
                align-items: center;
            }
            input[type="text"] {
                width: 80%;
                padding: 10px;
                margin-bottom: 20px;
                border: 1px solid #ccc;
                border-radius: 5px;
                font-size: 16px;
            }
            button {
                background-color: #4caf50;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 16px;
                border-radius: 5px;
                cursor: pointer;
            }
            button:hover {
                background-color: #45a049;
            }
            .result {
                margin-top: 20px;
                font-size: 18px;
                font-weight: bold;
            }
            .result.legitimate {
                color: #4caf50;
            }
            .result.phishing {
                color: #f44336;
            }
            .result.error {
                color: #ff9800;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Phishing Website Detector</h1>
            <form id="urlForm">
                <input type="text" id="url" placeholder="Enter website URL" required>
                <button type="button" onclick="predictUrl()">Check</button>
            </form>
            <div id="result" class="result"></div>
        </div>

        <script>
            function predictUrl() {
                var url = document.getElementById('url').value;
                var resultDiv = document.getElementById('result');
                resultDiv.textContent = "Checking...";
                resultDiv.className = "result";

                fetch('/predict', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({url: url})
                })
                .then(response => response.json())
                .then(data => {
                    if (data.prediction) {
                        resultDiv.textContent = "The website is classified as: " + data.prediction;
                        resultDiv.className = "result " + data.prediction.toLowerCase();
                    } else {
                        resultDiv.textContent = "Error: " + data.error;
                        resultDiv.className = "result error";
                    }
                })
                .catch(error => {
                    resultDiv.textContent = "An error occurred. Please try again.";
                    resultDiv.className = "result error";
                });
            }
        </script>
    </body>
    </html>
    """)

# API endpoint for prediction
@app.route('/predict', methods=['POST'])
def predict_website_legitimacy():
    if request.is_json:
        data = request.get_json()
        url = data.get('url')
        
        if url:
            features = extract_features_from_url(url)
            features_scaled = scaler.transform([features])
            prediction = model.predict(features_scaled)[0]

            result = {
                'url': url,
                'prediction': 'PHISHING' if prediction == 1 else 'LEGITIMATE'
            }
            return jsonify(result)
        else:
            return jsonify({"error": "URL is required"}), 400
    else:
        return jsonify({"error": "Request must be JSON"}), 400

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
