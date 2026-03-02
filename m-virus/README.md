# XGBoost Malware Detection Stack

End-to-end local stack for malware classification using EMBER-style features:
- training script (`scripts/xgboost_malware_detector.py`)
- inference scripts (`scripts/predict_malware.py`, `scripts/batch_detection.py`)
- FastAPI backend (`backend/api_backend.py`)
- React component (`frontend/MalwareDetector.jsx`)

## What is fixed in this version

- Shared inference core in `backend/model_core.py` (single source of truth)
- API/script/frontend contract aligned on dynamic `input_features`
- API reduced to frontend-focused endpoints for model stats + file upload
- Model metadata moved to `models/model_metadata.json` (used by `/model-info`)

## Quick Run

### 1) Start API

```powershell
cd a:\Documents\m-virus
.\.venv\Scripts\python.exe -m backend.api_backend
```

### 2) Validate API

```powershell
.\.venv\Scripts\python.exe scripts/test_api.py
```

### 3) Run predictions

```powershell
.\.venv\Scripts\python.exe scripts/predict_malware.py --file ember_dataset/test_features.jsonl --limit 10
.\.venv\Scripts\python.exe scripts/batch_detection.py --input ember_dataset/test_features.jsonl
```

## Train a model (EMBER)

```powershell
.\.venv\Scripts\python.exe scripts/xgboost_malware_detector.py --dataset-dir ember_dataset --train-limit 50000 --test-limit 10000
```

Useful flags:
- `--bodmas-limit 50000` (default): cap BODMAS samples used in training.
- `--no-include-bodmas`: force EMBER-only training.

Outputs:
- `models/xgboost_malware_model.json`
- `models/model_metadata.json`

## API Endpoints

- `GET /health`
- `GET /model-info`
- `POST /predict-file`
- `POST /scan-archive`

Interactive docs:
- `http://localhost:8000/docs`

## Notes on datasets

- Runtime and API are EMBER-format feature inference.
- Training script can include BODMAS by default using separate feature blocks (`EMBER block + BODMAS block + domain flag`).
- Disable BODMAS mixing with: `--no-include-bodmas`.
- `/predict-file` and `scripts/predict_pe_file.py` require optional EMBER extraction dependency from GitHub (`config/requirements-optional.txt`), typically on Python 3.10/3.11.
- `/predict-file` supports PE binaries such as `.exe`, `.dll`, `.sys`, `.scr`, `.drv`, `.cpl`, `.ocx`, `.efi`, `.mui` (or any file with `MZ` PE header).
- `.msi` is not a raw PE format; unpack MSI payloads first and scan extracted PE files.
- `/scan-archive` accepts `.zip`, `.tar(.gz/.bz2/.xz)`, `.rar`, `.7z` and scans PE-like entries inside.
- RAR/7z support is optional (`rarfile`, `py7zr` from `config/requirements-optional.txt`).
