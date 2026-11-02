import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import joblib

DATA_PATH = "dataset/clean_combined.csv"

REDUCED_FEATURES = [
    "Destination Port", "Flow Duration",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Std",
    "Max Packet Length", "Min Packet Length",
    "Packet Length Mean", "Packet Length Std",
    "Average Packet Size",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "Flow Bytes/s", "Flow Packets/s",
    "FIN Flag Count", "SYN Flag Count",
]

print("Loading data...")
df = pd.read_csv(DATA_PATH, low_memory=False)
X = df[REDUCED_FEATURES]
y = df["Binary_Label"].map({"BENIGN": 0, "ATTACK": 1})

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("Training reduced-feature XGBoost...")
xgb = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1, eval_metric="logloss")
xgb.fit(X_train, y_train)

y_pred = xgb.predict(X_test)
print("\nReduced XGBoost performance:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred))
print("Recall:", recall_score(y_test, y_pred))
print("F1:", f1_score(y_test, y_pred))
print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

joblib.dump(xgb, "models/saved/xgb_reduced.pkl")
print("\nSaved to models/saved/xgb_reduced.pkl")