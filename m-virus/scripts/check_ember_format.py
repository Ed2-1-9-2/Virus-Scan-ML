import json
from pathlib import Path

# Check EMBER data format
project_root = Path(__file__).resolve().parent.parent
ember_dir = project_root / "ember_dataset"
train_file = ember_dir / "train_features_0.jsonl"

print("Checking EMBER data format...")
print(f"File: {train_file}")
print(f"File exists: {train_file.exists()}")
print(f"File size: {train_file.stat().st_size / 1024 / 1024:.2f} MB")

print("\nFirst 3 lines:")
with open(train_file, 'r') as f:
    for i, line in enumerate(f):
        if i >= 3:
            break
        data = json.loads(line)
        print(f"\nLine {i+1}:")
        print(f"  Keys: {list(data.keys())}")
        if 'features' in data:
            print(f"  Features type: {type(data['features'])}")
            if isinstance(data['features'], list):
                print(f"  Features length: {len(data['features'])}")
                print(f"  First 5 features: {data['features'][:5]}")
        if 'label' in data:
            print(f"  Label: {data['label']}")
