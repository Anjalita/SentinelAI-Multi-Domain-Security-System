import pandas as pd

print("Starting web payload cleaning...")

# Load raw data
df = pd.read_csv("data/raw/web_payloads.csv")
print("Original shape:", df.shape)
print("Columns found:", df.columns.tolist())

# Rename columns
df = df.rename(columns={
    "Type": "label",
    "Payload": "payload"
})

# Normalize labels
df["label"] = df["label"].astype(str).str.upper().str.strip()
df["label"] = df["label"].replace({
    "SQL": "SQLI",
    "CMDINJ": "CMD_INJECTION",
    "TRAVERSAL": "PATH_TRAVERSAL"
})

# Drop duplicate payloads
df = df.drop_duplicates(subset=["payload"])

print("Cleaned shape:", df.shape)

# Save cleaned file
df.to_csv("data/processed/web_payloads_clean.csv", index=False)

print("Finished. Clean web payload dataset saved.")
