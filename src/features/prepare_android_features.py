import pandas as pd

print("Preparing Android malware features...")

# Load cleaned dataset
df = pd.read_csv("data/processed/android_malware_clean.csv")

print("Dataset shape:", df.shape)

# Separate features and label
X = df.drop(columns=["Label"])
y = df["Label"]

print("X shape:", X.shape)
print("y shape:", y.shape)

# Save features
X.to_csv("data/features/android_X.csv", index=False)
y.to_csv("data/features/android_y.csv", index=False)

print("Android features saved successfully.")

