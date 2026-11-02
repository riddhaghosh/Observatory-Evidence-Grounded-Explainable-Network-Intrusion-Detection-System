import pandas as pd
import numpy as np
import os

DATASET_DIR = "dataset"
OUTPUT_FILE = "dataset/clean_combined.csv"

files = [f for f in os.listdir(DATASET_DIR) if f.endswith(".csv")]

all_dfs = []

for f in files:
    path = os.path.join(DATASET_DIR, f)
    print(f"Loading {f} ...")
    df = pd.read_csv(path, low_memory=False, encoding="latin1")  # fixes the Web Attack encoding issue
    df.columns = df.columns.str.strip()  # fix leading-space column names
    all_dfs.append(df)

print("\nCombining all files...")
combined = pd.concat(all_dfs, ignore_index=True)
print("Combined shape before cleaning:", combined.shape)

# Fix the mangled Web Attack labels
combined["Label"] = combined["Label"].str.replace("Web Attack \x96", "Web Attack -", regex=False)
combined["Label"] = combined["Label"].str.replace("Web Attack �", "Web Attack -", regex=False)

# Replace infinities with NaN, then drop NaN rows
combined.replace([np.inf, -np.inf], np.nan, inplace=True)
before = combined.shape[0]
combined.dropna(inplace=True)
print(f"Dropped {before - combined.shape[0]} rows with NaN/Infinity")

# Drop duplicate rows
before = combined.shape[0]
combined.drop_duplicates(inplace=True)
print(f"Dropped {before - combined.shape[0]} duplicate rows")

# Create binary label: BENIGN vs ATTACK
combined["Binary_Label"] = combined["Label"].apply(lambda x: "BENIGN" if x == "BENIGN" else "ATTACK")

print("\nFinal shape:", combined.shape)
print("\nBinary label distribution:")
print(combined["Binary_Label"].value_counts())

print(f"\nSaving to {OUTPUT_FILE} ...")
combined.to_csv(OUTPUT_FILE, index=False)
print("Done.")