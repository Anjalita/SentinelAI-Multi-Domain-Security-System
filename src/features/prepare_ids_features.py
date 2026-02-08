import pandas as pd

print("Preparing IDS2018 features...")

df = pd.read_csv("data/processed/ids2018_clean.csv", low_memory=False)

# Target
y = df["Label"]

# Drop non-feature columns
drop_cols = [
    "Label",
    "Flow ID",
    "Src IP",
    "Dst IP",
    "Timestamp"
]

X = df.drop(columns=[c for c in drop_cols if c in df.columns])

# Save
X.to_csv("data/features/ids_X.csv", index=False)
y.to_csv("data/features/ids_y.csv", index=False)

print("IDS features prepared:")
print("X shape:", X.shape)
print("y shape:", y.shape)
