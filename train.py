import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
from sklearn.pipeline import Pipeline

# =========================
# LOAD DATASETS
# =========================

train_df = pd.read_csv("data/payload_train.csv")
test_df = pd.read_csv("data/payload_test.csv")

# =========================
# FEATURES + LABELS
# =========================

X_train = train_df["payload"]
y_train = train_df["label"]

X_test = test_df["payload"]
y_test = test_df["label"]

# =========================
# BUILD PIPELINE
# =========================

pipeline = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer='char',
            ngram_range=(1, 5)
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight='balanced'
        )
    )
])

# =========================
# TRAIN MODEL
# =========================

print("\nTraining model...\n")

pipeline.fit(X_train, y_train)

# =========================
# TEST MODEL
# =========================

predictions = pipeline.predict(X_test)

print("\nAccuracy:\n")
print(accuracy_score(y_test, predictions))

print("\nClassification Report:\n")
print(classification_report(y_test, predictions))

# =========================
# SAVE MODEL
# =========================

joblib.dump(pipeline, "models/sqli_model.pkl")

print("\nModel saved successfully.")
