import pandas as pd
import numpy as np
import joblib

DATA_PATH = "dataset/clean_combined.csv"
MODEL_PATH = "models/saved/xgboost_model.pkl"

print("Loading data and model...")
df = pd.read_csv(DATA_PATH, low_memory=False)
xgb = joblib.load(MODEL_PATH)

drop_cols = ["Label", "Binary_Label"]
X = df.drop(columns=drop_cols)
X = X.select_dtypes(include=["number"])

# Verify class encoding instead of assuming it — this was the source of a
# real bug in other scripts using RandomForest models (string labels sorted
# alphabetically put ATTACK at index 0, not 1).
print("Model classes (in order):", xgb.classes_)

# xgb.classes_ will be [0, 1] since XGBoost trained on numeric labels.
# We know from train_xgboost.py that ATTACK was mapped to 1, BENIGN to 0.
# Confirm that mapping explicitly here rather than assuming silently:
ATTACK_LABEL = 1  # matches y_numeric = y.map({"BENIGN": 0, "ATTACK": 1}) in training
attack_class_index = list(xgb.classes_).index(ATTACK_LABEL)
print(f"ATTACK corresponds to model.classes_[{attack_class_index}] = {xgb.classes_[attack_class_index]}")

print("Getting predictions and probabilities...")
preds = xgb.predict(X)
probs = xgb.predict_proba(X)[:, attack_class_index]  # probability of ATTACK class, looked up dynamically

# Get global feature importances (which features the model relies on most, overall)
importances = pd.Series(xgb.feature_importances_, index=X.columns)
top_features = importances.sort_values(ascending=False).head(5).index.tolist()
print("Top 5 globally important features:", top_features)

def build_evidence(row_idx):
    row = X.iloc[row_idx]
    evidence = {
        "row_index": int(row_idx),
        "prediction": "ATTACK" if preds[row_idx] == ATTACK_LABEL else "BENIGN",
        "confidence": round(float(probs[row_idx]), 4),
        "destination_port": int(row.get("Destination Port", -1)),
        "flow_duration": float(row.get("Flow Duration", -1)),
        "flow_bytes_per_sec": float(row.get("Flow Bytes/s", -1)),
        "flow_packets_per_sec": float(row.get("Flow Packets/s", -1)),
        "syn_flag_count": int(row.get("SYN Flag Count", -1)),
        "fin_flag_count": int(row.get("FIN Flag Count", -1)),
        "top_contributing_features": top_features
    }
    return evidence

# Example: build evidence for the first 5 rows predicted as ATTACK
attack_indices = np.where(preds == ATTACK_LABEL)[0][:5]
print("\nExample evidence for first 5 flagged ATTACK rows:\n")
for idx in attack_indices:
    ev = build_evidence(idx)
    print(ev)
    print()