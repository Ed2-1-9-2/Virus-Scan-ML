# Quick Start

## 1. Start API (local)

```powershell
cd a:\Documents\m-virus
.\.venv\Scripts\python.exe -m backend.api_backend
```

API endpoints:
- `http://localhost:8000/health`
- `http://localhost:8000/docs`

## 2. Validate API

```powershell
.\.venv\Scripts\python.exe scripts/test_api.py
```

Optional (for `/predict-file` and `scripts/predict_pe_file.py`):

```powershell
.\.venv\Scripts\pip.exe install -r config/requirements-optional.txt
```

Then verify extractor status:

```powershell
curl http://127.0.0.1:8010/health
```
Check:
- `"pe_file_extraction_available": true`

If this fails on Python 3.14, use a Python 3.10 venv for extraction:

```powershell
py -3.10 -m venv .venv310
.\.venv310\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r config/requirements-api.txt
pip install -r config/requirements-optional.txt
```

These optional deps also enable `/scan-archive` support for `.rar` and `.7z`.

## 3. Run predictions

Single / sample JSONL:

```powershell
.\.venv\Scripts\python.exe scripts/predict_malware.py --file ember_dataset/test_features.jsonl --limit 10
```

Batch scan:

```powershell
.\.venv\Scripts\python.exe scripts/batch_detection.py --input ember_dataset/test_features.jsonl
```

Local PE file -> API `/predict-file` request:

```powershell
.\.venv\Scripts\python.exe scripts/predict_pe_file.py --file C:\path\to\sample.exe --api-url http://localhost:8000
```

Outputs:
- `reports/malware_detection_summary.txt`
- optional CSV if `--output-csv` is used

## 4. Retrain model (optional)

```powershell
.\.venv\Scripts\python.exe scripts/xgboost_malware_detector.py --dataset-dir ember_dataset --train-limit 50000 --test-limit 10000
```

Artifacts:
- `models/xgboost_malware_model.json`
- `models/model_metadata.json`

## 5. React frontend (optional)

`frontend/MalwareDetector.jsx` reads API URL from `REACT_APP_API_URL`.

Default fallback:
- `http://localhost:8000`

## 6. Docker

Start backend service:

```powershell
docker compose up -d malware-api
```

Start frontend too (only if `./react-app` exists):

```powershell
docker compose --profile frontend up -d
```

## Notes

- The runtime model expects feature length from `model.num_features()` (not hardcoded).
- `models/model_metadata.json` is used by `/model-info` for reported metrics.
- Training now supports EMBER + BODMAS together via separate feature blocks (default in `scripts/xgboost_malware_detector.py`).
- Use `--no-include-bodmas` if you want EMBER-only retraining.
- Endpoint `/predict-file` needs optional `ember` dependency installed for PE feature extraction from `config/requirements-optional.txt`.
- `/predict-file` accepts PE formats: `.exe`, `.dll`, `.sys`, `.scr`, `.drv`, `.cpl`, `.ocx`, `.efi`, `.mui` (or any file with `MZ` header).
- `.msi` files are not raw PE and must be unpacked to PE payloads before scanning with EMBER features.
- Endpoint `/scan-archive` accepts `.zip`, `.tar(.gz/.bz2/.xz)`, `.rar`, `.7z` and scans PE payloads found in archive entries.
