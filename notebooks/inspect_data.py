import pandas as pd
import os

DATASET_DIR = "dataset"

# List all CSV files in the dataset folder
files = [f for f in os.listdir(DATASET_DIR) if f.endswith(".csv")]
print("Found files:")
for f in files:
    print(" -", f)

print("\n" + "="*60 + "\n")

# Inspect each file one by one
for f in files:
    path = os.path.join(DATASET_DIR, f)
    print(f"--- {f} ---")
    df = pd.read_csv(path, low_memory=False)
    print("Shape:", df.shape)
    print("Columns:", list(df.columns)[:5], "...")  # just first 5 to keep it readable
    print()