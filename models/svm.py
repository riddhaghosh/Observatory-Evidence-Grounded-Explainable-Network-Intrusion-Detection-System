import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib
import os

DATA_PATH = "dataset/clean_combined.csv"

print("Loading cleaned dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)

drop_cols = ["Label", "Binary_Label"]
X = df.drop(columns=drop_cols)
y = df["Binary_Label"]
X = X.select_dtypes(include=["number"])

# Subsample for SVM feasibility — stratified so class ratio is preserved
print("Original size:", X.shape[0])
X_sub, _, y_sub, _ = train_test_split(
    X, y, train_size=150000, random_state=42, stratify=y
)
print("Subsampled size for SVM:", X_sub.shape[0])

X_train, X_test, y_train, y_test = train_test_split(
    X_sub, y_sub, test_size=0.2, random_state=42, stratify=y_sub
)

# SVM is sensitive to feature scale — must standardize
print("\nScaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("\nTraining SVM (LinearSVC)...")
svm = LinearSVC(class_weight="balanced", random_state=42, max_iter=5000)
svm.fit(X_train_scaled, y_train)

print("\nEvaluating...")
y_pred = svm.predict(X_test_scaled)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred, pos_label="ATTACK"))
print("Recall:", recall_score(y_test, y_pred, pos_label="ATTACK"))
print("F1:", f1_score(y_test, y_pred, pos_label="ATTACK"))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nFull report:\n", classification_report(y_test, y_pred))

os.makedirs("models/saved", exist_ok=True)
joblib.dump(svm, "models/saved/svm_model.pkl")
joblib.dump(scaler, "models/saved/svm_scaler.pkl")  # save scaler too — needed at inference time
print("\nModel saved to models/saved/svm_model.pkl")