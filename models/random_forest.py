import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib
import os

DATA_PATH = "dataset/clean_combined.csv"

print("Loading cleaned dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)

# Drop columns that would leak the answer or aren't useful features
drop_cols = ["Label", "Binary_Label"]
X = df.drop(columns=drop_cols)
y = df["Binary_Label"]

# Keep only numeric columns (some flow features may load as object/string)
X = X.select_dtypes(include=["number"])

print("Feature matrix shape:", X.shape)
print("Target distribution:\n", y.value_counts())

# Train/test split (stratify keeps the same class ratio in both sets)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\nTraining Random Forest...")
rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    random_state=42,
    n_jobs=-1,          # use all CPU cores
    class_weight="balanced"
)
rf.fit(X_train, y_train)

print("\nEvaluating...")
y_pred = rf.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred, pos_label="ATTACK"))
print("Recall:", recall_score(y_test, y_pred, pos_label="ATTACK"))
print("F1:", f1_score(y_test, y_pred, pos_label="ATTACK"))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("\nFull report:\n", classification_report(y_test, y_pred))

# Save the trained model
os.makedirs("models/saved", exist_ok=True)
joblib.dump(rf, "models/saved/random_forest.pkl")
print("\nModel saved to models/saved/random_forest.pkl")