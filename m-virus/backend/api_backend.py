"""FastAPI backend for the XGBoost malware detector."""

from __future__ import annotations

from contextlib import asynccontextmanager
import io
import os
import sys
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.model_core import (
    LightGBMMalwareModel,
    RandomForestMalwareModel,
    URLPhishingModel,
    XGBoostMalwareModel,
    flatten_ember_features,
)
from backend.pe_to_features import (
    extract_raw_from_bytes,
    extract_model_features_from_bytes,
    extractor_diagnostics,
    extractor_available,
    sha256_bytes,
)


XGBOOST_MODEL_PATH = Path(
    os.getenv("MODEL_PATH", PROJECT_ROOT / "models" / "xgboost_malware_model.json")
)
XGBOOST_METADATA_PATH = Path(
    os.getenv("MODEL_METADATA_PATH", PROJECT_ROOT / "models" / "model_metadata.json")
)
LIGHTGBM_MODEL_PATH = Path(
    os.getenv("LIGHTGBM_MODEL_PATH", PROJECT_ROOT / "models" / "lightgbm_malware_model.txt")
)
LIGHTGBM_METADATA_PATH = Path(
    os.getenv("LIGHTGBM_METADATA_PATH", PROJECT_ROOT / "models" / "lightgbm_model_metadata.json")
)
RANDOM_FOREST_MODEL_PATH_ENV = os.getenv("RANDOM_FOREST_MODEL_PATH")
RANDOM_FOREST_METADATA_PATH = Path(
    os.getenv(
        "RANDOM_FOREST_METADATA_PATH",
        PROJECT_ROOT / "models" / "random_forest_model_metadata.json",
    )
)
URL_PHISH_MODEL_PATH = Path(
    os.getenv("URL_PHISH_MODEL_PATH", PROJECT_ROOT / "models" / "url_phishing_model.joblib")
)
URL_PHISH_METADATA_PATH = Path(
    os.getenv(
        "URL_PHISH_METADATA_PATH",
        PROJECT_ROOT / "models" / "url_phishing_model_metadata.json",
    )
)
PE_ALLOWED_SUFFIXES = (
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".com",
    ".ax",
    ".tlb",
    ".ime",
    ".acm",
    ".drv",
    ".cpl",
    ".ocx",
    ".efi",
    ".mui",
)
MSI_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
RAR_MAGIC_V4 = b"Rar!\x1A\x07\x00"
RAR_MAGIC_V5 = b"Rar!\x1A\x07\x01\x00"
SEVEN_Z_MAGIC = b"7z\xBC\xAF\x27\x1C"
MAX_ARCHIVE_BYTES = int(os.getenv("MAX_ARCHIVE_BYTES", "209715200"))  # 200 MB
MAX_ARCHIVE_ENTRIES = int(os.getenv("MAX_ARCHIVE_ENTRIES", "5000"))
MAX_ARCHIVE_MEMBER_BYTES = int(os.getenv("MAX_ARCHIVE_MEMBER_BYTES", "26214400"))  # 25 MB
MAX_ARCHIVE_SCAN_FILES = int(os.getenv("MAX_ARCHIVE_SCAN_FILES", "1000"))
ARCHIVE_SUPPORTED_FORMATS = [".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".rar", ".7z"]
FRONTEND_BUILD_DIR = Path(
    os.getenv("FRONTEND_BUILD_DIR", str(PROJECT_ROOT.parent / "m-virus-ui" / "build"))
).resolve()
FRONTEND_INDEX_FILE = FRONTEND_BUILD_DIR / "index.html"
FRONTEND_STATIC_DIR = FRONTEND_BUILD_DIR / "static"


def _resolve_random_forest_model_path() -> Path:
    """Resolve RandomForest model path with backward-compatible fallbacks."""
    if RANDOM_FOREST_MODEL_PATH_ENV and RANDOM_FOREST_MODEL_PATH_ENV.strip():
        return Path(RANDOM_FOREST_MODEL_PATH_ENV.strip())

    candidates = [
        PROJECT_ROOT / "models" / "random_forest_malware_model.joblib",
        PROJECT_ROOT / "models" / "random_forest_model.joblib",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


RANDOM_FOREST_MODEL_PATH = _resolve_random_forest_model_path()


def _parse_allowed_origins() -> tuple[List[str], bool]:
    raw = os.getenv("ALLOWED_ORIGINS", "*")
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    if not origins:
        origins = ["*"]

    # Browsers reject allow_credentials=True with wildcard origin.
    allow_credentials = "*" not in origins
    return origins, allow_credentials


def frontend_build_available() -> bool:
    """Return True when production frontend assets are available."""
    return FRONTEND_INDEX_FILE.exists() and FRONTEND_STATIC_DIR.exists()


def _resolve_frontend_asset(asset_path: str) -> Optional[Path]:
    """Resolve a build asset path safely (prevent path traversal)."""
    if not asset_path:
        return None

    candidate = (FRONTEND_BUILD_DIR / asset_path).resolve()
    if candidate != FRONTEND_BUILD_DIR and FRONTEND_BUILD_DIR not in candidate.parents:
        return None

    if candidate.is_file():
        return candidate
    return None


allowed_origins, allow_credentials = _parse_allowed_origins()

runtime_model: Optional[XGBoostMalwareModel] = None
runtime_predict_models: Dict[str, Any] = {}
runtime_unavailable_models: Dict[str, str] = {}
runtime_url_model: Optional[URLPhishingModel] = None
runtime_url_model_error: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global runtime_model, runtime_predict_models, runtime_unavailable_models
    global runtime_url_model, runtime_url_model_error
    runtime_predict_models = {}
    runtime_unavailable_models = {}
    runtime_url_model = None
    runtime_url_model_error = None

    runtime_model = XGBoostMalwareModel(
        model_path=XGBOOST_MODEL_PATH,
        metadata_path=XGBOOST_METADATA_PATH,
    )
    runtime_predict_models["xgboost"] = runtime_model
    print(f"Model loaded [xgboost]: {XGBOOST_MODEL_PATH}")
    print(f"Feature count: {runtime_model.feature_count}")

    try:
        runtime_predict_models["lightgbm"] = LightGBMMalwareModel(
            model_path=LIGHTGBM_MODEL_PATH,
            metadata_path=LIGHTGBM_METADATA_PATH,
        )
        print(f"Model loaded [lightgbm]: {LIGHTGBM_MODEL_PATH}")
    except Exception as exc:
        runtime_unavailable_models["lightgbm"] = str(exc)
        print(f"Model unavailable [lightgbm]: {exc}")

    try:
        runtime_predict_models["random_forest"] = RandomForestMalwareModel(
            model_path=RANDOM_FOREST_MODEL_PATH,
            metadata_path=RANDOM_FOREST_METADATA_PATH,
        )
        print(f"Model loaded [random_forest]: {RANDOM_FOREST_MODEL_PATH}")
    except Exception as exc:
        runtime_unavailable_models["random_forest"] = str(exc)
        print(f"Model unavailable [random_forest]: {exc}")

    try:
        runtime_url_model = URLPhishingModel(
            model_path=URL_PHISH_MODEL_PATH,
            metadata_path=URL_PHISH_METADATA_PATH,
        )
        print(f"Model loaded [url_phishing]: {URL_PHISH_MODEL_PATH}")
    except Exception as exc:
        runtime_url_model_error = str(exc)
        print(f"Model unavailable [url_phishing]: {exc}")

    print(f"Comparative models available: {list(runtime_predict_models.keys())}")
    try:
        yield
    finally:
        print("API shutdown")


app = FastAPI(
    title="Malware Detector API",
    description="REST API for malware detection with comparative multi-model scoring.",
    version="1.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PredictionResponse(BaseModel):
    prediction: str
    probability_malware: float
    confidence: float
    sha256: Optional[str] = None


class ModelPredictionResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    model_name: str
    model_type: str
    prediction: str
    probability_malware: float
    confidence: float
    threshold: float
    input_features: int


class PredictionComparisonResponse(PredictionResponse):
    file_name: str
    file_type: str
    primary_model: str
    consensus_prediction: str
    consensus_probability_malware: float
    consensus_confidence: float
    votes: Dict[str, int]
    models: Dict[str, ModelPredictionResponse]
    unavailable_models: Dict[str, str]


class URLPredictionRequest(BaseModel):
    url: str


class URLPredictionResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    url: str
    normalized_url: str
    prediction: str
    probability_phishing: float
    confidence: float
    threshold: float
    model_type: str
    created_at: str


class ArchiveFileResult(BaseModel):
    file_name: str
    prediction: str
    probability_malware: float
    confidence: float
    sha256: Optional[str] = None


class ArchiveScanResponse(BaseModel):
    archive_name: str
    archive_type: str
    total_entries: int
    scanned_files: int
    malware_count: int
    benign_count: int
    failed_files: int
    skipped_entries: int
    truncated: bool
    average_confidence: float
    results: List[ArchiveFileResult]
    timestamp: str


def require_model() -> XGBoostMalwareModel:
    if runtime_model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")
    return runtime_model


def require_predict_models() -> Dict[str, Any]:
    if not runtime_predict_models:
        raise HTTPException(status_code=500, detail="No prediction models loaded")
    return runtime_predict_models


def require_url_model() -> URLPhishingModel:
    if runtime_url_model is None:
        detail = "URL phishing model is not loaded."
        if runtime_url_model_error:
            detail = (
                f"{detail} {runtime_url_model_error} "
                "Train it with scripts/train_phishing_url_model.py and restart backend."
            )
        raise HTTPException(status_code=503, detail=detail)
    return runtime_url_model


def _pick_primary_model_name(model_names: Iterable[str]) -> str:
    names = set(model_names)
    for preferred in ("lightgbm", "xgboost", "random_forest"):
        if preferred in names:
            return preferred
    return sorted(names)[0]


def _is_probable_pe(filename: str, data: bytes) -> bool:
    lower_name = filename.lower()
    return lower_name.endswith(PE_ALLOWED_SUFFIXES) or data.startswith(b"MZ")


def _detect_archive_type(filename: str, data: bytes) -> str:
    lower_name = (filename or "").lower()
    head = data[:8]
    bio = io.BytesIO(data)

    if zipfile.is_zipfile(bio) or lower_name.endswith(".zip"):
        return "zip"

    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*"):
            return "tar"
    except Exception:
        pass

    if head.startswith(RAR_MAGIC_V4) or head.startswith(RAR_MAGIC_V5) or lower_name.endswith(".rar"):
        return "rar"

    if head.startswith(SEVEN_Z_MAGIC) or lower_name.endswith(".7z"):
        return "7z"

    return "unknown"


def _iter_zip_entries(data: bytes) -> Iterable[Tuple[str, bytes]]:
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            with zf.open(info, "r") as member:
                yield info.filename, member.read()


def _iter_tar_entries(data: bytes) -> Iterable[Tuple[str, bytes]]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            yield member.name, extracted.read()


def _iter_rar_entries(data: bytes) -> Iterable[Tuple[str, bytes]]:
    try:
        import rarfile  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "RAR support missing. Install optional dependency 'rarfile' and ensure unrar/bsdtar is available."
        ) from exc

    with rarfile.RarFile(io.BytesIO(data)) as rf:
        for info in rf.infolist():
            if info.isdir():
                continue
            with rf.open(info) as member:
                yield info.filename, member.read()


def _iter_7z_entries(data: bytes) -> Iterable[Tuple[str, bytes]]:
    try:
        import py7zr  # type: ignore
    except Exception as exc:
        raise RuntimeError("7z support missing. Install optional dependency 'py7zr'.") from exc

    with py7zr.SevenZipFile(io.BytesIO(data), mode="r") as archive:
        content = archive.readall()
        for name, handle in content.items():
            raw = handle.read()
            yield name, raw


def _iter_archive_entries(archive_type: str, data: bytes) -> Iterable[Tuple[str, bytes]]:
    if archive_type == "zip":
        yield from _iter_zip_entries(data)
        return
    if archive_type == "tar":
        yield from _iter_tar_entries(data)
        return
    if archive_type == "rar":
        yield from _iter_rar_entries(data)
        return
    if archive_type == "7z":
        yield from _iter_7z_entries(data)
        return

    raise RuntimeError("Unsupported archive format. Supported: zip, tar, rar, 7z.")


@app.get("/")
async def root():
    return {
        "name": "Multi-Model Malware Detector API",
        "version": app.version,
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    model = runtime_model
    loaded_models = sorted(runtime_predict_models.keys())
    return {
        "status": "healthy" if model is not None else "degraded",
        "model_loaded": model is not None,
        "model_path": str(XGBOOST_MODEL_PATH),
        "input_features": model.feature_count if model else None,
        "loaded_prediction_models": loaded_models,
        "unavailable_prediction_models": dict(runtime_unavailable_models),
        "url_model_loaded": runtime_url_model is not None,
        "url_model_path": str(URL_PHISH_MODEL_PATH),
        "url_model_error": runtime_url_model_error,
        "pe_file_extraction_available": extractor_available(),
        "pe_file_extraction_diagnostics": extractor_diagnostics(),
        "frontend_build_available": frontend_build_available(),
        "frontend_app_path": "/app" if frontend_build_available() else None,
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/predict-file", response_model=PredictionComparisonResponse)
async def predict_file(file: UploadFile = File(...)):
    predict_models = require_predict_models()

    if not extractor_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "PE file extraction is unavailable. "
                f"{extractor_diagnostics()}"
            ),
        )

    filename = file.filename or "uploaded_file"

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    lower_name = filename.lower()
    if lower_name.endswith(".msi") or data.startswith(MSI_MAGIC):
        raise HTTPException(
            status_code=422,
            detail=(
                "MSI is not a raw PE binary, so EMBER PE features cannot be extracted directly. "
                "Extract contained PE payloads first (.exe/.dll/.sys/etc.), then scan those files."
            ),
        )

    is_known_pe_extension = lower_name.endswith(PE_ALLOWED_SUFFIXES)
    is_pe_magic = data.startswith(b"MZ")
    if not (is_known_pe_extension or is_pe_magic):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file type: {filename}. "
                f"Accepted PE extensions: {', '.join(PE_ALLOWED_SUFFIXES)} "
                "or any file with PE magic header (MZ)."
            ),
        )

    if not is_pe_magic:
        raise HTTPException(
            status_code=400,
            detail=(
                f"File does not appear to be a valid PE binary (missing MZ header): {filename}"
            ),
        )

    try:
        raw = extract_raw_from_bytes(data)
        base_features = flatten_ember_features(raw)
        if base_features.size == 0:
            raise RuntimeError("Feature extractor produced an empty feature vector")

        file_sha = sha256_bytes(data)
        model_results: Dict[str, ModelPredictionResponse] = {}
        unavailable_models = dict(runtime_unavailable_models)

        for model_name, model_obj in predict_models.items():
            try:
                model_pred = model_obj.predict_one(features=base_features, sha256=file_sha)
                model_results[model_name] = ModelPredictionResponse(
                    model_name=model_name,
                    model_type=model_obj.metadata.get("model_type", model_obj.__class__.__name__),
                    prediction=model_pred["prediction"],
                    probability_malware=float(model_pred["probability_malware"]),
                    confidence=float(model_pred["confidence"]),
                    threshold=float(model_obj.threshold),
                    input_features=int(model_obj.feature_count),
                )
            except Exception as model_exc:
                unavailable_models[model_name] = f"Prediction failed: {model_exc}"

        if not model_results:
            raise HTTPException(
                status_code=503,
                detail=(
                    "No prediction models could analyze this file. "
                    f"Failures: {unavailable_models}"
                ),
            )

        primary_model_name = _pick_primary_model_name(model_results.keys())
        primary_result = model_results[primary_model_name]

        malware_votes = sum(
            1 for result in model_results.values() if result.prediction == "Malware"
        )
        benign_votes = len(model_results) - malware_votes
        if malware_votes > benign_votes:
            consensus_prediction = "Malware"
        elif benign_votes > malware_votes:
            consensus_prediction = "Benign"
        else:
            consensus_prediction = primary_result.prediction

        consensus_probability = float(
            sum(result.probability_malware for result in model_results.values())
            / len(model_results)
        )
        consensus_confidence = float(max(consensus_probability, 1.0 - consensus_probability))

        return PredictionComparisonResponse(
            prediction=primary_result.prediction,
            probability_malware=primary_result.probability_malware,
            confidence=primary_result.confidence,
            sha256=file_sha,
            file_name=filename,
            file_type="pe",
            primary_model=primary_model_name,
            consensus_prediction=consensus_prediction,
            consensus_probability_malware=consensus_probability,
            consensus_confidence=consensus_confidence,
            votes={"malware": malware_votes, "benign": benign_votes},
            models=model_results,
            unavailable_models=unavailable_models,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not extract PE features: {exc}") from exc


@app.post("/predict-url", response_model=URLPredictionResponse)
async def predict_url(request: URLPredictionRequest):
    model = require_url_model()

    raw_url = (request.url or "").strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL is empty")
    if len(raw_url) > 8192:
        raise HTTPException(status_code=400, detail="URL is too long (max 8192 characters)")

    try:
        result = model.predict_one(raw_url)
        return URLPredictionResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not analyze URL: {exc}") from exc


@app.post("/scan-archive", response_model=ArchiveScanResponse)
async def scan_archive(
    file: UploadFile = File(...),
    result_limit: int = Query(200, ge=0, le=2000),
):
    model = require_model()

    if not extractor_available():
        raise HTTPException(
            status_code=503,
            detail=("PE file extraction is unavailable. " f"{extractor_diagnostics()}"),
        )

    archive_name = file.filename or "uploaded_archive"
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded archive is empty")
    if len(data) > MAX_ARCHIVE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Archive is too large ({len(data)} bytes). Max allowed: {MAX_ARCHIVE_BYTES} bytes.",
        )

    archive_type = _detect_archive_type(archive_name, data)
    if archive_type == "unknown":
        raise HTTPException(
            status_code=400,
            detail="Unsupported archive format. Supported: .zip, .tar(.gz/.bz2/.xz), .rar, .7z",
        )

    results: List[ArchiveFileResult] = []
    malware_count = 0
    benign_count = 0
    failed_files = 0
    skipped_entries = 0
    scanned_files = 0
    total_entries = 0
    truncated = False
    confidences: List[float] = []

    try:
        for entry_name, entry_data in _iter_archive_entries(archive_type, data):
            total_entries += 1
            if total_entries > MAX_ARCHIVE_ENTRIES:
                skipped_entries += 1
                truncated = True
                break

            if len(entry_data) > MAX_ARCHIVE_MEMBER_BYTES:
                skipped_entries += 1
                continue

            if entry_data.startswith(MSI_MAGIC):
                skipped_entries += 1
                continue

            if not _is_probable_pe(entry_name, entry_data):
                skipped_entries += 1
                continue

            if not entry_data.startswith(b"MZ"):
                skipped_entries += 1
                continue

            if scanned_files >= MAX_ARCHIVE_SCAN_FILES:
                skipped_entries += 1
                truncated = True
                break

            try:
                features, _raw = extract_model_features_from_bytes(entry_data, model.feature_count)
                file_sha = sha256_bytes(entry_data)
                prediction = model.predict_one(features=features, sha256=file_sha)

                scanned_files += 1
                confidences.append(float(prediction["confidence"]))
                if prediction["prediction"] == "Malware":
                    malware_count += 1
                else:
                    benign_count += 1

                if len(results) < max(0, int(result_limit)):
                    results.append(
                        ArchiveFileResult(
                            file_name=entry_name,
                            prediction=prediction["prediction"],
                            probability_malware=float(prediction["probability_malware"]),
                            confidence=float(prediction["confidence"]),
                            sha256=prediction.get("sha256"),
                        )
                    )
            except Exception:
                failed_files += 1
    except RuntimeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not process archive: {exc}") from exc

    avg_conf = float(sum(confidences) / len(confidences)) if confidences else 0.0
    return ArchiveScanResponse(
        archive_name=archive_name,
        archive_type=archive_type,
        total_entries=total_entries,
        scanned_files=scanned_files,
        malware_count=malware_count,
        benign_count=benign_count,
        failed_files=failed_files,
        skipped_entries=skipped_entries,
        truncated=truncated,
        average_confidence=avg_conf,
        results=results,
        timestamp=datetime.now().isoformat(),
    )


@app.get("/model-info")
async def model_info():
    model = require_model()
    meta = model.metadata

    metrics = meta.get("metrics", {}) if isinstance(meta.get("metrics"), dict) else {}
    loaded_models: Dict[str, Dict[str, Any]] = {}
    for model_name, model_obj in runtime_predict_models.items():
        model_meta = model_obj.metadata if isinstance(model_obj.metadata, dict) else {}
        loaded_models[model_name] = {
            "model_name": model_name,
            "model_type": model_meta.get("model_type", model_obj.__class__.__name__),
            "model_path": str(model_obj.model_path),
            "input_features": int(model_obj.feature_count),
            "threshold": float(model_obj.threshold),
            "metrics": model_meta.get("metrics"),
            "confusion_matrix": model_meta.get("confusion_matrix"),
            "roc_curve_points": model_meta.get("roc_curve_points"),
            "correlation_matrix": model_meta.get("correlation_matrix"),
            "correlation_labels": model_meta.get("correlation_labels"),
            "training_samples": model_meta.get("training_samples"),
            "test_samples": model_meta.get("test_samples"),
            "created_at": model_meta.get("created_at"),
            "notes": model_meta.get("notes"),
            "training_info": model_meta.get("training_info"),
        }

    primary_model_name = (
        _pick_primary_model_name(loaded_models.keys()) if loaded_models else None
    )
    url_model_info: Dict[str, Any]
    if runtime_url_model is not None:
        url_meta = (
            runtime_url_model.metadata
            if isinstance(runtime_url_model.metadata, dict)
            else {}
        )
        url_model_info = {
            "loaded": True,
            "model_name": "url_phishing",
            "model_type": runtime_url_model.model_type,
            "model_path": str(runtime_url_model.model_path),
            "metadata_path": str(runtime_url_model.metadata_path),
            "input_features": runtime_url_model.feature_count,
            "threshold": runtime_url_model.threshold,
            "metrics": url_meta.get("metrics"),
            "confusion_matrix": url_meta.get("confusion_matrix"),
            "roc_curve_points": url_meta.get("roc_curve_points"),
            "correlation_matrix": url_meta.get("correlation_matrix"),
            "correlation_labels": url_meta.get("correlation_labels"),
            "training_samples": url_meta.get("training_samples"),
            "test_samples": url_meta.get("test_samples"),
            "notes": url_meta.get("notes"),
            "training_info": url_meta.get("training_info"),
            "created_at": url_meta.get("created_at", runtime_url_model.created_at),
        }
    else:
        url_model_info = {
            "loaded": False,
            "model_name": "url_phishing",
            "model_path": str(URL_PHISH_MODEL_PATH),
            "metadata_path": str(URL_PHISH_METADATA_PATH),
            "error": runtime_url_model_error,
        }

    return {
        "model_type": meta.get("model_type", "XGBoost Binary Classifier"),
        "model_path": str(model.model_path),
        "input_features": model.feature_count,
        "output_classes": 2,
        "classes": ["Benign", "Malware"],
        "threshold": model.threshold,
        "predict_file_mode": "comparative_multi_model",
        "predict_file_primary_model": primary_model_name,
        "models_catalog": sorted(loaded_models.keys()),
        "loaded_prediction_models": loaded_models,
        "unavailable_prediction_models": dict(runtime_unavailable_models),
        "predict_url_enabled": runtime_url_model is not None,
        "predict_url_model": url_model_info,
        "predict_url_notes": (
            "POST /predict-url performs lexical phishing detection on the URL string only. "
            "It does not fetch the webpage content."
        ),
        "predict_file_supported_extensions": list(PE_ALLOWED_SUFFIXES),
        "predict_file_support_notes": (
            "Comparative scoring runs all loaded models (LightGBM/XGBoost/RandomForest) on the same PE features. "
            "Supports known PE extensions and any file with valid MZ header. "
            "Formats like .msi require unpacking to PE payloads before scanning."
        ),
        "predict_archive_supported_formats": ARCHIVE_SUPPORTED_FORMATS,
        "predict_archive_support_notes": (
            "Archive scanning extracts files in-memory and evaluates PE payloads from archive entries. "
            "RAR/7z require optional dependencies."
        ),
        "predict_archive_limits": {
            "max_archive_bytes": MAX_ARCHIVE_BYTES,
            "max_archive_entries": MAX_ARCHIVE_ENTRIES,
            "max_archive_member_bytes": MAX_ARCHIVE_MEMBER_BYTES,
            "max_archive_scan_files": MAX_ARCHIVE_SCAN_FILES,
        },
        "pe_file_extraction_available": extractor_available(),
        "pe_file_extraction_diagnostics": extractor_diagnostics(),
        "training_samples": meta.get("training_samples"),
        "test_samples": meta.get("test_samples"),
        "accuracy": metrics.get("accuracy"),
        "roc_auc": metrics.get("roc_auc"),
        "precision": metrics.get("precision"),
        "recall": metrics.get("recall"),
        "f1_score": metrics.get("f1_score"),
        "confusion_matrix": meta.get("confusion_matrix"),
        "roc_curve_points": meta.get("roc_curve_points"),
        "correlation_matrix": meta.get("correlation_matrix"),
        "correlation_labels": meta.get("correlation_labels"),
        "created_at": meta.get("created_at"),
        "notes": meta.get("notes"),
        "bodmas_included": meta.get("bodmas_included"),
        "training_info": meta.get("training_info"),
        "frontend_build_available": frontend_build_available(),
        "frontend_app_path": "/app" if frontend_build_available() else None,
    }


@app.get("/frontend-status")
async def frontend_status():
    return {
        "frontend_build_available": frontend_build_available(),
        "frontend_build_dir": str(FRONTEND_BUILD_DIR),
        "frontend_index_file": str(FRONTEND_INDEX_FILE),
        "frontend_app_path": "/app" if frontend_build_available() else None,
    }


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error": True},
    )


if frontend_build_available():
    app.mount(
        "/app/static",
        StaticFiles(directory=str(FRONTEND_STATIC_DIR)),
        name="frontend_static",
    )

    @app.get("/app", include_in_schema=False)
    @app.get("/app/", include_in_schema=False)
    async def frontend_index():
        return FileResponse(str(FRONTEND_INDEX_FILE))

    @app.get("/app/{asset_path:path}", include_in_schema=False)
    async def frontend_asset(asset_path: str):
        target = _resolve_frontend_asset(asset_path)
        if target is not None:
            return FileResponse(str(target))
        return FileResponse(str(FRONTEND_INDEX_FILE))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
