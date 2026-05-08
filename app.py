from flask import Flask, request, jsonify
import joblib

# =========================
# LOAD MODEL
# =========================

model = joblib.load("models/sqli_model.pkl")

# =========================
# CREATE FLASK APP
# =========================

app = Flask(__name__)

# =========================
# HOME ROUTE
# =========================

@app.route("/")
def home():
    return "SQL Injection Detection API Running"

# =========================
# PREDICTION ROUTE
# =========================

@app.route("/predict", methods=["POST"])
def predict():

    data = request.get_json()

    payload = data.get("payload")

    if not payload:
        return jsonify({
            "error": "No payload provided"
        }), 400

    prediction = model.predict([payload])[0]

    if prediction == "anom":
        result = "SQL Injection"
        malicious = True
    else:
        result = "Normal"
        malicious = False

    return jsonify({
        "payload": payload,
        "prediction": result,
        "is_malicious": malicious
    })

# =========================
# RUN SERVER
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
