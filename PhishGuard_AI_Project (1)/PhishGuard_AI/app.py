from pathlib import Path
from datetime import datetime
import csv
import io
import sqlite3
import joblib

from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model" / "phishing_model.joblib"
DB_PATH = BASE_DIR / "phishguard.db"
ALLOWED_EXTENSIONS = {"txt", "csv"}
MAX_MESSAGE_LENGTH = 10000

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB upload limit

model = None
if MODEL_PATH.exists():
    model = joblib.load(MODEL_PATH)

def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection

def initialize_database():
    with get_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                risk_score INTEGER NOT NULL,
                indicators TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

initialize_database()

def inspect_message(message):
    """Simple transparent indicators to support—not replace—the ML prediction."""
    text = message.lower()
    indicators = []

    if "http://" in text or "https://" in text or "www." in text:
        indicators.append("Contains a web link. Check the domain carefully.")
    if any(word in text for word in ["urgent", "immediately", "24 hours", "act now", "suspended"]):
        indicators.append("Uses urgent or threatening language.")
    if any(word in text for word in ["otp", "password", "pin", "cvv", "bank details"]):
        indicators.append("Mentions sensitive credentials or banking information.")
    if any(word in text for word in ["prize", "winner", "won", "lottery", "claim your"]):
        indicators.append("Promises a prize, reward, or unexpected benefit.")
    if any(word in text for word in ["upi", "payment", "transfer money", "send money", "refund"]):
        indicators.append("Mentions a payment, transfer, or refund.")
    if any(word in text for word in ["verify your account", "click here", "update your account", "kyc"]):
        indicators.append("Requests account verification or encourages clicking.")
    if not indicators:
        indicators.append("No common warning phrase was detected. Still verify the sender.")

    return indicators

def analyze_message(message):
    global model
    if model is None:
        raise RuntimeError("The AI model is missing. Run: python train_model.py")

    cleaned = message.strip()
    if not cleaned:
        raise ValueError("Please enter a message.")
    if len(cleaned) > MAX_MESSAGE_LENGTH:
        raise ValueError("Message is too long. Maximum length is 10,000 characters.")

    probabilities = model.predict_proba([cleaned])[0]
    classes = list(model.classes_)
    spam_probability = float(probabilities[classes.index(1)])
    prediction = "Phishing" if spam_probability >= 0.5 else "Legitimate"

    indicators = inspect_message(cleaned)
    # This is a heuristic risk indicator, not a calibrated probability.
    indicator_count = sum(
        phrase in " ".join(indicators).lower()
        for phrase in ["web link", "urgent", "credentials", "prize", "payment", "verification"]
    )
    risk_score = round(min(100, spam_probability * 75 + indicator_count * 5))
    if prediction == "Legitimate":
        risk_score = min(risk_score, 49)

    confidence = max(spam_probability, 1 - spam_probability) * 100
    return {
        "prediction": prediction,
        "confidence": round(confidence, 1),
        "spam_probability": round(spam_probability * 100, 1),
        "risk_score": int(risk_score),
        "indicators": indicators,
        "advice": (
            "Do not click links or share OTPs, passwords, PINs, or banking details. "
            "Verify the request using the organisation's official app or phone number."
            if prediction == "Phishing"
            else
            "The model did not classify this as phishing. This does not prove it is safe. "
            "Check the sender and links independently before taking action."
        )
    }

def save_scan(message, result):
    with get_db() as connection:
        connection.execute("""
            INSERT INTO scans
            (message, prediction, confidence, risk_score, indicators, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            message[:MAX_MESSAGE_LENGTH],
            result["prediction"],
            result["confidence"],
            result["risk_score"],
            " | ".join(result["indicators"]),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

def extract_uploaded_text(file):
    filename = secure_filename(file.filename or "")
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Upload only .txt or .csv files.")

    raw = file.read()
    if not raw:
        raise ValueError("The uploaded file is empty.")
    text = raw.decode("utf-8-sig", errors="replace")

    if extension == "txt":
        return text.strip()

    rows = list(csv.reader(io.StringIO(text)))
    messages = []
    for row in rows:
        cells = [cell.strip() for cell in row if cell.strip()]
        if cells:
            # If a CSV has multiple columns, combine non-empty cells for analysis.
            messages.append(" ".join(cells))
    return "\n".join(messages).strip()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/detect", methods=["POST"])
def detect():
    try:
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            message = str(payload.get("message", "")).strip()
        else:
            uploaded = request.files.get("file")
            if uploaded and uploaded.filename:
                message = extract_uploaded_text(uploaded)
            else:
                message = request.form.get("message", "").strip()

        result = analyze_message(message)
        save_scan(message, result)
        return jsonify({"success": True, "message": message, "result": result})
    except (ValueError, RuntimeError) as error:
        return jsonify({"success": False, "error": str(error)}), 400
    except Exception:
        return jsonify({"success": False, "error": "Something went wrong while analyzing this message."}), 500

@app.route("/api/history")
def history():
    with get_db() as connection:
        rows = connection.execute(
            "SELECT id, message, prediction, confidence, risk_score, created_at "
            "FROM scans ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return jsonify([dict(row) for row in rows])

@app.route("/api/stats")
def stats():
    with get_db() as connection:
        total = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        phishing = connection.execute(
            "SELECT COUNT(*) FROM scans WHERE prediction='Phishing'"
        ).fetchone()[0]
        legitimate = total - phishing
        average_risk = connection.execute(
            "SELECT AVG(risk_score) FROM scans"
        ).fetchone()[0]
    return jsonify({
        "total": total,
        "phishing": phishing,
        "legitimate": legitimate,
        "average_risk": round(average_risk or 0, 1)
    })

@app.errorhandler(413)
def file_too_large(_error):
    return jsonify({"success": False, "error": "File is too large. Maximum upload size is 1 MB."}), 413

if __name__ == "__main__":
    if model is None:
        print("AI model not found. First run: python train_model.py")
    else:
        print("PhishGuard AI is running. Open http://127.0.0.1:5000")
    app.run(debug=True)
