import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib
import numpy as np

DATA_PATH = "dataset/clean_combined.csv"

print("Loading cleaned dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)

drop_cols = ["Label", "Binary_Label"]
X = df.drop(columns=drop_cols)
y = df["Binary_Label"]
X = X.select_dtypes(include=["number"])

# Same split as RF/XGBoost so results are comparable
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Loading trained models...")
rf = joblib.load("models/saved/random_forest.pkl")
xgb = joblib.load("models/saved/xgboost_model.pkl")
svm = joblib.load("models/saved/svm_model.pkl")
svm_scaler = joblib.load("models/saved/svm_scaler.pkl")

print("Getting predictions from each model...")
rf_pred = rf.predict(X_test)                          # returns "BENIGN"/"ATTACK"
xgb_pred_num = xgb.predict(X_test)                     # returns 0/1
xgb_pred = np.where(xgb_pred_num == 1, "ATTACK", "BENIGN")

X_test_scaled = svm_scaler.transform(X_test)
svm_pred = svm.predict(X_test_scaled)                  # returns "BENIGN"/"ATTACK"

print("\nCombining via majority vote...")
# Stack predictions and take majority vote (2 out of 3)
votes = pd.DataFrame({"rf": rf_pred, "xgb": xgb_pred, "svm": svm_pred})
def majority_vote(row):
    attack_votes = sum(row == "ATTACK")
    return "ATTACK" if attack_votes >= 2 else "BENIGN"

ensemble_pred = votes.apply(majority_vote, axis=1)

print("\nEnsemble Evaluation:")
print("Accuracy:", accuracy_score(y_test, ensemble_pred))
print("Precision:", precision_score(y_test, ensemble_pred, pos_label="ATTACK"))
print("Recall:", recall_score(y_test, ensemble_pred, pos_label="ATTACK"))
print("F1:", f1_score(y_test, ensemble_pred, pos_label="ATTACK"))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, ensemble_pred))
print("\nFull report:\n", classification_report(y_test, ensemble_pred))