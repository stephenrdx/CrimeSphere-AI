import pandas as pd
from pathlib import Path

DATA_DIR = Path("data/raw")

files = list(DATA_DIR.glob("*.csv"))

print("Number of CSV files:", len(files))
print()

for file in files:
    df = pd.read_csv(file)
    print(f"{file.name:30} {len(df):5} records")