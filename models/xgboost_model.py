import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from xgboost import XGBClassifier
import joblib
import os

DATA_PATH = "dataset/clean_combined.csv"

print("Loading cleaned dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)

drop_cols = ["Label", "Binary_Label"]
X = df.drop(columns=drop_cols)
y = df["Binary_Label"]
X = X.select_dtypes(include=["number"])

# XGBoost needs numeric labels, not strings
y_numeric = y.map({"BENIGN": 0, "ATTACK": 1})

X_train, X_test, y_train, y_test = train_test_split(
    X, y_numeric, test_size=0.2, random_state=42, stratify=y_numeric
)

print("\nTraining XGBoost...")
xgb = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss"
)
xgb.fit(X_train, y_train)

print("\nEvaluating...")
y_pred = xgb.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred))
print("Recall:", recall_score(y_test, y_pred))
print("F1:", f1_score(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nFull report:\n", classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

os.makedirs("models/saved", exist_ok=True)
joblib.dump(xgb, "models/saved/xgboost_model.pkl")
print("\nModel saved to models/saved/xgboost_model.pkl")