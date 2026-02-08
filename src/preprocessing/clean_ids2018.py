import pandas as pd

print("Starting...")

# read the original file
df = pd.read_csv("data/raw/IDS2018.csv", low_memory=False)

print("Original rows, columns:", df.shape)

# keep numeric columns
numeric_columns = df.select_dtypes(include=["number"]).columns.tolist()

# keep label column if it exists
columns_to_keep = numeric_columns
if "Label" in df.columns:
    columns_to_keep.append("Label")

df_clean = df[columns_to_keep]

# save cleaned copy
df_clean.to_csv("data/processed/ids2018_clean.csv", index=False)

print("Finished. Clean file created.")
