"""FastAPI backend for the XGBoost malware detector."""

from __future__ import annotations

from contextlib import asynccontextmanager
import hmac
import io
import json
import os
import re
import smtplib
import ssl
import sys
import tarfile
import zipfile
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from threading import Lock
from typing import Dict, Iterable, List, Optional, Tuple

from fastapi import FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _load_local_env_file(path: Path) -> None:
    """Load KEY=VALUE lines from local env file if present."""
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not key:
            continue

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        os.environ.setdefault(key, value)


_load_local_env_file(PROJECT_ROOT / ".env.smtp.local")
_load_local_env_file(PROJECT_ROOT / ".env.smtp")

from backend.model_core import XGBoostMalwareModel
from backend.pe_to_features import (
    extract_model_features_from_bytes,
    extractor_diagnostics,
    extractor_available,
    sha256_bytes,
)


MODEL_PATH = Path(
    os.getenv("MODEL_PATH", PROJECT_ROOT / "models" / "xgboost_malware_model.json")
)
MODEL_METADATA_PATH = Path(
    os.getenv("MODEL_METADATA_PATH", PROJECT_ROOT / "models" / "model_metadata.json")
)
PE_ALLOWED_SUFFIXES = (
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".drv",
    ".cpl",
    ".ocx",
    ".efi",
    ".mui",
)
CONTACT_DEFAULT_RECIPIENTS = [
    "badinabogdan21@stud.ase.ro",
    "voicueduard22@stud.ase.ro",
    "chiriacmario21@stud.ase.ro",
]
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MSI_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
RAR_MAGIC_V4 = b"Rar!\x1A\x07\x00"
RAR_MAGIC_V5 = b"Rar!\x1A\x07\x01\x00"
SEVEN_Z_MAGIC = b"7z\xBC\xAF\x27\x1C"
MAX_ARCHIVE_BYTES = int(os.getenv("MAX_ARCHIVE_BYTES", "209715200"))  # 200 MB
MAX_ARCHIVE_ENTRIES = int(os.getenv("MAX_ARCHIVE_ENTRIES", "5000"))
MAX_ARCHIVE_MEMBER_BYTES = int(os.getenv("MAX_ARCHIVE_MEMBER_BYTES", "26214400"))  # 25 MB
MAX_ARCHIVE_SCAN_FILES = int(os.getenv("MAX_ARCHIVE_SCAN_FILES", "1000"))
ARCHIVE_SUPPORTED_FORMATS = [".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".rar", ".7z"]
CONTACT_MESSAGES_PATH = Path(
    os.getenv("CONTACT_MESSAGES_PATH", PROJECT_ROOT / "reports" / "contact_messages.txt")
)
CONTACT_ADMIN_MAX_LIMIT = int(os.getenv("CONTACT_ADMIN_MAX_LIMIT", "500"))
ADMIN_PAGE_PASSWORD = os.getenv("ADMIN_PAGE_PASSWORD", "test")
CONTACT_FILE_LOCK = Lock()
DEFAULT_ROC_CURVE_POINTS = [
    [0.0, 0.0],
    [0.01, 0.36],
    [0.03, 0.61],
    [0.06, 0.75],
    [0.1, 0.84],
    [0.18, 0.91],
    [0.3, 0.95],
    [1.0, 1.0],
]
DEFAULT_CORRELATION_LABELS = [
    "Byte entropy",
    "PE headers",
    "Import graph",
    "Section stats",
    "String signals",
]
DEFAULT_CORRELATION_MATRIX = [
    [1.0, 0.72, -0.18, 0.54, 0.33],
    [0.72, 1.0, -0.12, 0.47, 0.28],
    [-0.18, -0.12, 1.0, -0.41, -0.22],
    [0.54, 0.47, -0.41, 1.0, 0.36],
    [0.33, 0.28, -0.22, 0.36, 1.0],
]


def _parse_allowed_origins() -> tuple[List[str], bool]:
    raw = os.getenv("ALLOWED_ORIGINS", "*")
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    if not origins:
        origins = ["*"]

    # Browsers reject allow_credentials=True with wildcard origin.
    allow_credentials = "*" not in origins
    return origins, allow_credentials


def _to_float(value: object, fallback: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return fallback
    if parsed != parsed:  # NaN
        return fallback
    return parsed


def _normalize_confusion_matrix(matrix: object) -> List[List[int]]:
    if (
        isinstance(matrix, list)
        and len(matrix) == 2
        and all(isinstance(row, list) and len(row) == 2 for row in matrix)
    ):
        return [
            [max(0, int(round(_to_float(matrix[0][0], 0.0)))), max(0, int(round(_to_float(matrix[0][1], 0.0))))],
            [max(0, int(round(_to_float(matrix[1][0], 0.0)))), max(0, int(round(_to_float(matrix[1][1], 0.0))))],
        ]
    return [[0, 0], [0, 0]]


def _normalize_roc_curve_points(points: object) -> List[List[float]]:
    if not isinstance(points, list):
        return DEFAULT_ROC_CURVE_POINTS

    normalized: List[List[float]] = []
    for item in points:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue
        x = min(1.0, max(0.0, _to_float(item[0], 0.0)))
        y = min(1.0, max(0.0, _to_float(item[1], 0.0)))
        normalized.append([x, y])

    if len(normalized) < 2:
        return DEFAULT_ROC_CURVE_POINTS

    normalized.sort(key=lambda pair: (pair[0], pair[1]))
    if normalized[0][0] > 0.0:
        normalized.insert(0, [0.0, 0.0])
    if normalized[-1][0] < 1.0:
        normalized.append([1.0, 1.0])
    return normalized


def _normalize_correlation_matrix(matrix: object) -> List[List[float]]:
    if not isinstance(matrix, list) or not matrix:
        return DEFAULT_CORRELATION_MATRIX

    parsed_rows: List[List[float]] = []
    for row in matrix:
        if not isinstance(row, list) or not row:
            continue
        parsed_rows.append([max(-1.0, min(1.0, _to_float(value, 0.0))) for value in row])

    if not parsed_rows:
        return DEFAULT_CORRELATION_MATRIX

    min_width = min(len(row) for row in parsed_rows)
    size = min(len(parsed_rows), min_width)
    if size < 2:
        return DEFAULT_CORRELATION_MATRIX

    return [row[:size] for row in parsed_rows[:size]]


def _normalize_correlation_labels(labels: object, size: int) -> List[str]:
    if size <= 0:
        return []
    if isinstance(labels, list):
        normalized = [str(label).strip() for label in labels if str(label).strip()]
        if len(normalized) >= size:
            return normalized[:size]

    if size == len(DEFAULT_CORRELATION_LABELS):
        return DEFAULT_CORRELATION_LABELS
    return [f"Feature {idx + 1}" for idx in range(size)]


allowed_origins, allow_credentials = _parse_allowed_origins()

runtime_model: Optional[XGBoostMalwareModel] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global runtime_model
    runtime_model = XGBoostMalwareModel(
        model_path=MODEL_PATH,
        metadata_path=MODEL_METADATA_PATH,
    )
    print(f"Model loaded: {MODEL_PATH}")
    print(f"Feature count: {runtime_model.feature_count}")
    try:
        yield
    finally:
        print("API shutdown")


app = FastAPI(
    title="XGBoost Malware Detector API",
    description="REST API for malware detection using XGBoost.",
    version="1.1.0",
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


class ContactMessageRequest(BaseModel):
    name: str
    email: str
    subject: str
    message: str


class ContactMessageResponse(BaseModel):
    success: bool
    detail: str
    message_id: str
    saved_to: str
    recipients: List[str]


class ContactMessageRecord(BaseModel):
    message_id: str
    created_at: str
    name: str
    email: str
    subject: str
    message: str


class ContactMessagesResponse(BaseModel):
    total: int
    items: List[ContactMessageRecord]


def require_model() -> XGBoostMalwareModel:
    if runtime_model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")
    return runtime_model


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


def _contact_recipients() -> List[str]:
    raw = os.getenv("CONTACT_TO_EMAILS")
    if raw:
        recipients = [item.strip() for item in raw.split(",") if item.strip()]
    else:
        recipients = CONTACT_DEFAULT_RECIPIENTS.copy()
    return recipients


def _validate_contact_payload(payload: ContactMessageRequest) -> ContactMessageRequest:
    name = payload.name.strip()
    email = payload.email.strip()
    subject = payload.subject.strip()
    message = payload.message.strip()

    if len(name) < 2 or len(name) > 120:
        raise HTTPException(status_code=422, detail="Name must be between 2 and 120 characters.")
    if len(subject) < 3 or len(subject) > 180:
        raise HTTPException(status_code=422, detail="Subject must be between 3 and 180 characters.")
    if len(message) < 10 or len(message) > 5000:
        raise HTTPException(status_code=422, detail="Message must be between 10 and 5000 characters.")
    if not EMAIL_PATTERN.match(email):
        raise HTTPException(status_code=422, detail="Sender email is invalid.")

    return ContactMessageRequest(
        name=name,
        email=email,
        subject=subject,
        message=message,
    )


def _persist_contact_message(payload: ContactMessageRequest) -> ContactMessageRecord:
    CONTACT_MESSAGES_PATH.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().isoformat()
    message_id = f"msg-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    record = ContactMessageRecord(
        message_id=message_id,
        created_at=timestamp,
        name=payload.name,
        email=payload.email,
        subject=payload.subject,
        message=payload.message,
    )

    serialized = json.dumps(record.model_dump(), ensure_ascii=False)
    with CONTACT_FILE_LOCK:
        with CONTACT_MESSAGES_PATH.open("a", encoding="utf-8") as handle:
            handle.write(serialized + "\n")

    return record


def _read_contact_messages(limit: int = 100) -> List[ContactMessageRecord]:
    if not CONTACT_MESSAGES_PATH.exists():
        return []

    rows: List[ContactMessageRecord] = []
    safe_limit = max(1, min(limit, CONTACT_ADMIN_MAX_LIMIT))

    with CONTACT_FILE_LOCK:
        lines = CONTACT_MESSAGES_PATH.read_text(encoding="utf-8").splitlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            rows.append(ContactMessageRecord(**parsed))
        except Exception:
            # Skip malformed rows without interrupting admin page.
            continue

    return list(reversed(rows[-safe_limit:]))


def _assert_admin_access(password: Optional[str]) -> None:
    provided = (password or "").strip()
    if not provided or not hmac.compare_digest(provided, ADMIN_PAGE_PASSWORD):
        raise HTTPException(status_code=401, detail="Admin authentication failed.")


def _send_contact_email(payload: ContactMessageRequest) -> List[str]:
    smtp_host = os.getenv("CONTACT_SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("CONTACT_SMTP_PORT", "587"))
    smtp_user = os.getenv("CONTACT_SMTP_USER", "").strip()
    smtp_password = os.getenv("CONTACT_SMTP_PASSWORD", "").strip()
    smtp_secure = os.getenv("CONTACT_SMTP_SECURE", "starttls").strip().lower()
    sender = os.getenv("CONTACT_FROM_EMAIL", smtp_user).strip()
    recipients = _contact_recipients()

    if not smtp_host or not sender:
        raise HTTPException(
            status_code=503,
            detail=(
                "Contact mail service is not configured. "
                "Set CONTACT_SMTP_HOST and CONTACT_FROM_EMAIL (or CONTACT_SMTP_USER)."
            ),
        )
    if not recipients:
        raise HTTPException(status_code=503, detail="No contact recipients configured.")
    if smtp_user and not smtp_password:
        raise HTTPException(
            status_code=503,
            detail="CONTACT_SMTP_PASSWORD is required when CONTACT_SMTP_USER is set.",
        )

    email_message = EmailMessage()
    email_message["Subject"] = f"[m-virus] {payload.subject}"
    email_message["From"] = sender
    email_message["To"] = ", ".join(recipients)
    email_message["Reply-To"] = payload.email
    email_message.set_content(
        "\n".join(
            [
                "New contact request from m-virus UI",
                f"Timestamp: {datetime.now().isoformat()}",
                f"Name: {payload.name}",
                f"Sender: {payload.email}",
                "",
                "Message:",
                payload.message,
            ]
        )
    )

    timeout_seconds = 20
    try:
        if smtp_secure == "ssl":
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(
                host=smtp_host,
                port=smtp_port,
                timeout=timeout_seconds,
                context=context,
            ) as server:
                if smtp_user:
                    server.login(smtp_user, smtp_password)
                server.send_message(email_message)
        else:
            with smtplib.SMTP(host=smtp_host, port=smtp_port, timeout=timeout_seconds) as server:
                server.ehlo()
                if smtp_secure == "starttls":
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()
                if smtp_user:
                    server.login(smtp_user, smtp_password)
                server.send_message(email_message)
    except smtplib.SMTPAuthenticationError as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Email authentication failed (SMTP 535). "
                "Check CONTACT_SMTP_USER/CONTACT_SMTP_PASSWORD and verify that SMTP access "
                "is enabled for this mailbox."
            ),
        ) from exc
    except smtplib.SMTPException as exc:
        raise HTTPException(status_code=502, detail=f"Email delivery failed: {exc}") from exc
    except OSError as exc:
        raise HTTPException(status_code=502, detail=f"Email service connection failed: {exc}") from exc

    return recipients


@app.get("/")
async def root():
    return {
        "name": "XGBoost Malware Detector API",
        "version": app.version,
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    model = runtime_model
    return {
        "status": "healthy" if model is not None else "degraded",
        "model_loaded": model is not None,
        "model_path": str(MODEL_PATH),
        "input_features": model.feature_count if model else None,
        "pe_file_extraction_available": extractor_available(),
        "pe_file_extraction_diagnostics": extractor_diagnostics(),
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/predict-file", response_model=PredictionResponse)
async def predict_file(file: UploadFile = File(...)):
    model = require_model()

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
        features, _raw = extract_model_features_from_bytes(data, model.feature_count)
        file_sha = sha256_bytes(data)
        result = model.predict_one(features=features, sha256=file_sha)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not extract PE features: {exc}") from exc


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
    confusion_matrix = _normalize_confusion_matrix(meta.get("confusion_matrix"))
    roc_curve_points = _normalize_roc_curve_points(meta.get("roc_curve_points"))
    correlation_matrix = _normalize_correlation_matrix(meta.get("correlation_matrix"))
    correlation_labels = _normalize_correlation_labels(meta.get("correlation_labels"), len(correlation_matrix))

    return {
        "model_type": meta.get("model_type", "XGBoost Binary Classifier"),
        "model_path": str(model.model_path),
        "input_features": model.feature_count,
        "output_classes": 2,
        "classes": ["Benign", "Malware"],
        "threshold": model.threshold,
        "predict_file_supported_extensions": list(PE_ALLOWED_SUFFIXES),
        "predict_file_support_notes": (
            "EMBER extractor supports PE binaries only. "
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
        "confusion_matrix": confusion_matrix,
        "roc_curve_points": roc_curve_points,
        "correlation_labels": correlation_labels,
        "correlation_matrix": correlation_matrix,
        "created_at": meta.get("created_at"),
        "notes": meta.get("notes"),
        "bodmas_included": meta.get("bodmas_included"),
        "training_info": meta.get("training_info"),
    }


@app.post("/contact-message", response_model=ContactMessageResponse)
async def contact_message(payload: ContactMessageRequest):
    validated = _validate_contact_payload(payload)
    saved = _persist_contact_message(validated)
    recipients = _contact_recipients()
    return ContactMessageResponse(
        success=True,
        detail="Message saved successfully.",
        message_id=saved.message_id,
        saved_to=str(CONTACT_MESSAGES_PATH),
        recipients=recipients,
    )


@app.get("/admin/contact-messages", response_model=ContactMessagesResponse)
async def admin_contact_messages(
    limit: int = Query(100, ge=1, le=1000),
    x_admin_password: Optional[str] = Header(default=None, alias="X-Admin-Password"),
):
    _assert_admin_access(x_admin_password)
    rows = _read_contact_messages(limit=limit)
    return ContactMessagesResponse(
        total=len(rows),
        items=rows,
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error": True},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
