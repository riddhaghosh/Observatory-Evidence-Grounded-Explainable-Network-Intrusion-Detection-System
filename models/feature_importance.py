import pandas as pd
import joblib

MODEL_PATH = "models/saved/random_forest.pkl"
DATA_PATH = "dataset/clean_combined.csv"

print("Loading model and data...")
rf = joblib.load(MODEL_PATH)
df = pd.read_csv(DATA_PATH, nrows=1)  # just need column names

drop_cols = ["Label", "Binary_Label"]
X_cols = df.drop(columns=drop_cols).select_dtypes(include=["number"]).columns

importances = pd.Series(rf.feature_importances_, index=X_cols)
top20 = importances.sort_values(ascending=False).head(20)

print("\nTop 20 most important features (Random Forest):\n")
for feat, score in top20.items():
    print(f"{feat:40s} {score:.4f}")

# Also check XGBoost for comparison
print("\n" + "="*60)
xgb = joblib.load("models/saved/xgboost_model.pkl")
importances_xgb = pd.Series(xgb.feature_importances_, index=X_cols)
top20_xgb = importances_xgb.sort_values(ascending=False).head(20)

print("\nTop 20 most important features (XGBoost):\n")
for feat, score in top20_xgb.items():
    print(f"{feat:40s} {score:.4f}")