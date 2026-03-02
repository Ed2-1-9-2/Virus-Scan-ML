# Documentation Index

## Core Runtime
- `backend/api_backend.py`: FastAPI server
- `backend/model_core.py`: shared inference/feature utilities
- `scripts/predict_malware.py`: single/file JSONL prediction
- `scripts/batch_detection.py`: batch JSONL scan + summary reports
- `scripts/predict_pe_file.py`: local PE file extraction + API prediction helper
- `scripts/xgboost_malware_detector.py`: EMBER training script

## Main Docs
- `docs/QUICK_START.md`: fastest path to run API + scripts
- `README.md`: project overview and architecture
- `docs/DEPLOYMENT_GUIDE.md`: deployment notes
- `docs/INTEGRATION_GUIDE.md`: frontend/backend integration details
- `docs/MODEL_REPORT.md`: model metrics and evaluation report

## Validation
- `scripts/test_api.py`: API smoke/integration checks
- `config/requirements-api.txt`: backend dependencies

## Model Artifacts
- `models/xgboost_malware_model.json`: XGBoost model
- `models/model_metadata.json`: metrics + runtime metadata consumed by `/model-info`

## Dataset Assets
- `ember_dataset/`: EMBER JSONL files
- `bodmas/bodmas.npz`: BODMAS feature matrix (different feature space)
- `MalMem2022.csv`: memory-based dataset
