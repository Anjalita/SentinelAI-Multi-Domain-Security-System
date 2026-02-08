import pandas as pd

datasets = {
    "IDS2018": "data/processed/ids2018_clean.csv",
    "Benign Only": "data/processed/benign_clean.csv",
    "Android Malware": "data/processed/android_malware_clean.csv",
    "Web payload": "data/processed/web_payloads_clean.csv"
    
}

print("\n📊 LABEL DISTRIBUTION SUMMARY\n")

for name, path in datasets.items():
    print(f"--- {name} ---")
    df = pd.read_csv(path, low_memory=False)

    if "Label" not in df.columns:
        print(" No Label column found\n")
        continue

    print(df["Label"].value_counts())
    print()


