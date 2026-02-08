import pandas as pd

print("Starting benign dataset cleaning...")

# read benign dataset
df = pd.read_csv("data/raw/1.benign.csv", low_memory=False)

print("Original rows, columns:", df.shape)

# keep only numeric columns
numeric_columns = df.select_dtypes(include=["number"]).columns.tolist()
df_clean = df[numeric_columns]

# add label column
df_clean["Label"] = "BENIGN"

# save clean copy
df_clean.to_csv("data/processed/benign_clean.csv", index=False)

print("Finished. Benign clean file created.")
