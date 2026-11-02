import pandas as pd
import os

DATASET_DIR = "dataset"
files = [f for f in os.listdir(DATASET_DIR) if f.endswith(".csv")]

for f in files:
    path = os.path.join(DATASET_DIR, f)
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()   # fix the leading-space issue
    print(f"--- {f} ---")
    print(df["Label"].value_counts())
    print()