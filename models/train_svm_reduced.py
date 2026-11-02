import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC
from sklearn.preprocessing import StandardScaler
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

# Subsample for SVM feasibility, same approach as the original SVM training
X_sub, _, y_sub, _ = train_test_split(X, y, train_size=150000, random_state=42, stratify=y)

X_train, X_test, y_train, y_test = train_test_split(X_sub, y_sub, test_size=0.2, random_state=42, stratify=y_sub)

print("Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("Training reduced-feature SVM (LinearSVC)...")
svm = LinearSVC(class_weight="balanced", random_state=42, max_iter=5000)
svm.fit(X_train_scaled, y_train)

y_pred = svm.predict(X_test_scaled)
print("\nReduced SVM performance:")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred, pos_label="ATTACK"))
print("Recall:", recall_score(y_test, y_pred, pos_label="ATTACK"))
print("F1:", f1_score(y_test, y_pred, pos_label="ATTACK"))
print(classification_report(y_test, y_pred))

joblib.dump(svm, "models/saved/svm_reduced.pkl")
joblib.dump(scaler, "models/saved/svm_reduced_scaler.pkl")
print("\nSaved to models/saved/svm_reduced.pkl")