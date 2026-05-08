import joblib

# Load model
model = joblib.load("models/sqli_model.pkl")

# Test payloads
samples = [
    "' OR 1=1--",
    "' UNION SELECT password FROM users--",
    "hello world",
    "admin",
    "search product",
    "1' AND sleep(5)--"
]

print("\nTesting payloads:\n")

for payload in samples:

    prediction = model.predict([payload])[0]

    if prediction == "anom":
        result = "SQL Injection"
    else:
        result = "Normal"

    print(f"{payload} --> {result}")
