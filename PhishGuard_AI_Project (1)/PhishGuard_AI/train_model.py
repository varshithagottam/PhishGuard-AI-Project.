
from pathlib import Path
import pandas as pd
import joblib

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "model"
MODEL_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)


def main():
    dataset_path = DATA_DIR / "SMSSpamCollection"

    if not dataset_path.exists():
        print(f"Dataset not found: {dataset_path}")
        print("Place SMSSpamCollection inside the data folder.")
        return
    print("Loading dataset...")
    df = pd.read_csv(
        dataset_path,
        sep="\t",
        header=None,
        names=["label", "message"],
        encoding="utf-8",
        on_bad_lines="skip"
    )
    df = df.dropna(subset=["label", "message"])
    df["label"] = df["label"].map({"ham": 0, "spam": 1})
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, classification_report

    X_train, X_test, y_train, y_test = train_test_split(
        df["message"], df["label"],
        test_size=0.2, random_state=42, stratify=df["label"]
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            max_features=30000,
            sublinear_tf=True
        )),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        ))
    ])

    print("Training the machine-learning model...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"\nTest accuracy: {accuracy:.3f}")
    print("\nClassification report:")
    print(classification_report(y_test, predictions, target_names=["Legitimate", "Phishing/Spam"]))

    model_path = MODEL_DIR / "phishing_model.joblib"
    joblib.dump(model, model_path)
    print(f"\nModel saved to: {model_path}")
    print("Training complete. Now run: python app.py")

if __name__ == "__main__":
    main()
