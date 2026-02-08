import joblib

# Load trained NLP components
vectorizer = joblib.load("models/web_tfidf_vectorizer.pkl")
model = joblib.load("models/web_attack_classifier.pkl")

print("✅ Web attack detection system loaded successfully")
print("Type a payload to test (type 'exit' to quit)\n")

while True:
    text = input("🌐 Web Input > ")

    if text.lower() == "exit":
        print("Exiting...")
        break

    # Convert raw text → numerical features
    X = vectorizer.transform([text])

    # Predict attack type
    prediction = model.predict(X)[0]

    # Simple alert logic
    if prediction != "BENIGN":
        print(f"🚨 ALERT: {prediction} attack detected!\n")
    else:
        print("✅ BENIGN request\n")

