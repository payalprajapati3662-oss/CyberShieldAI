import pandas as pd
import joblib
from pathlib import Path

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# Project folders
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

# Dataset column names
columns = [
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
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty"
]

print("Loading dataset...")

train_data = pd.read_csv(
    DATA_DIR / "KDDTrain+.txt",
    header=None,
    names=columns
)

test_data = pd.read_csv(
    DATA_DIR / "KDDTest+.txt",
    header=None,
    names=columns
)

# Convert attack names into two classes
y_train = (train_data["label"] != "normal").astype(int)
y_test = (test_data["label"] != "normal").astype(int)

# Remove label and difficulty columns
X_train = train_data.drop(columns=["label", "difficulty"])
X_test = test_data.drop(columns=["label", "difficulty"])

# Identify text and numeric features
categorical_features = ["protocol_type", "service", "flag"]
numeric_features = [
    col for col in X_train.columns
    if col not in categorical_features
]

# Prepare the data
preprocessor = ColumnTransformer([
    ("categorical", OneHotEncoder(handle_unknown="ignore"),
     categorical_features),
    ("numeric", StandardScaler(), numeric_features)
])

# Create the ML model
model = Pipeline([
    ("preprocessor", preprocessor),
    ("classifier", RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    ))
])

print("Training model...")

model.fit(X_train, y_train)

print("Testing model...")

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

# Save the trained model
model_path = BASE_DIR / "cyber_model.joblib"
joblib.dump(model, model_path)

print(f"Model accuracy: {accuracy * 100:.2f}%")
print(f"Model saved at: {model_path}")
print("Training completed successfully!")