from flask import Flask, render_template, request
import joblib
import pandas as pd
import sqlite3
from pathlib import Path
from datetime import datetime

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
model = joblib.load(BASE_DIR / "cyber_model.joblib")
DB_PATH = BASE_DIR / "cyber_history.db"

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                prediction TEXT NOT NULL
            )
        """)

init_db()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["GET", "POST"])
def predict():
    if request.method == "POST":
        try:
            data = {}

            for feature in FEATURES:
                value = request.form.get(feature, "").strip()

                if not value:
                    return "Please fill in every field.", 400

                if feature in CATEGORICAL_FEATURES:
                    data[feature] = value
                else:
                    number = float(value)

                    if not pd.notna(number) or number < 0:
                        return "Enter valid non-negative numbers.", 400

                    data[feature] = number

            input_data = pd.DataFrame([data], columns=FEATURES)
            prediction_value = int(model.predict(input_data)[0])

            result_text = (
                "Attack Detected"
                if prediction_value == 1
                else "Normal Traffic"
            )

            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO scans (scan_time, prediction) VALUES (?, ?)",
                    (
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        result_text
                    )
                )

            return render_template(
                "result.html",
                prediction=result_text
            )

        except (ValueError, TypeError):
            return "Please enter valid numeric values.", 400

    return render_template(
        "predict.html",
        features=FEATURES,
        categorical_features=CATEGORICAL_FEATURES
    )

@app.route("/result")
def result():
    return render_template("result.html", prediction=None)

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/history")
def history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        scans = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()

    return render_template("history.html", scans=scans)

if __name__ == "__main__":
    app.run(debug=True)