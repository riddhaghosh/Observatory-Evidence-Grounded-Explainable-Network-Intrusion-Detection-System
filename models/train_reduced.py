import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
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
y = df["Binary_Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Training reduced-feature Random Forest...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight="balanced")
rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)

print("\nReduced-feature model performance:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred, pos_label="ATTACK"))
print("Recall:", recall_score(y_test, y_pred, pos_label="ATTACK"))
print("F1:", f1_score(y_test, y_pred, pos_label="ATTACK"))
print("\n", classification_report(y_test, y_pred))

joblib.dump(rf, "models/saved/rf_reduced.pkl")
print("\nSaved to models/saved/rf_reduced.pkl")