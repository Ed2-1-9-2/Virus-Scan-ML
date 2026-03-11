"""FastAPI backend for the XGBoost malware detector."""

from __future__ import annotations

from contextlib import asynccontextmanager
import io
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import sys
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
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
AUTH_DB_PATH = Path(os.getenv("AUTH_DB_PATH", PROJECT_ROOT / "backend" / "auth.db")).resolve()
AUTH_PASSWORD_ITERATIONS = int(os.getenv("AUTH_PASSWORD_ITERATIONS", "310000"))
AUTH_MIN_PASSWORD_LENGTH = int(os.getenv("AUTH_MIN_PASSWORD_LENGTH", "8"))
AUTH_ADMIN_USERS = {
    value.strip().lower()
    for value in str(os.getenv("AUTH_ADMIN_USERS", "")).split(",")
    if value.strip()
}


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
    _init_auth_db()

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


class AuthRequest(BaseModel):
    username: str
    password: str


class AuthResponse(BaseModel):
    token: str
    username: str
    is_admin: bool = False


class AuthenticatedUser(BaseModel):
    user_id: int
    username: str
    token: str
    is_admin: bool = False


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


def _db_connect() -> sqlite3.Connection:
    AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(AUTH_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _init_auth_db() -> None:
    with _db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);"
        )

        # Backward-compatible migration for databases created before admin support.
        user_columns = {
            str(row["name"])
            for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "is_admin" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;")

        # Ensure there is at least one admin account.
        admin_count = int(
            conn.execute("SELECT COUNT(*) AS count FROM users WHERE is_admin = 1").fetchone()["count"]
        )
        if admin_count == 0:
            first_user = conn.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1").fetchone()
            if first_user is not None:
                conn.execute(
                    "UPDATE users SET is_admin = 1 WHERE id = ?",
                    (int(first_user["id"]),),
                )


def _normalize_username(raw: str) -> str:
    username = str(raw or "").strip()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must have at least 3 characters.")
    if len(username) > 128:
        raise HTTPException(status_code=400, detail="Username/email is too long.")

    # Accept either classic username or email-based login.
    username_re = r"^[A-Za-z0-9._-]{3,64}$"
    email_re = r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,63}$"
    if not (re.fullmatch(username_re, username) or re.fullmatch(email_re, username)):
        raise HTTPException(
            status_code=400,
            detail=(
                "Username/email invalid. Use either 3-64 chars "
                "(letters, numbers, dot, underscore, hyphen) "
                "or a valid email address."
            ),
        )
    return username


def _validate_password(raw: str) -> str:
    password = str(raw or "")
    if len(password) < AUTH_MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must have at least {AUTH_MIN_PASSWORD_LENGTH} characters.",
        )
    if len(password) > 256:
        raise HTTPException(status_code=400, detail="Password is too long.")
    return password


def _hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        AUTH_PASSWORD_ITERATIONS,
    )
    return digest.hex()


def _create_session(conn: sqlite3.Connection, user_id: int) -> str:
    now = datetime.utcnow().isoformat()
    token = secrets.token_urlsafe(48)
    conn.execute(
        "INSERT INTO sessions(token, user_id, created_at, last_seen_at) VALUES (?, ?, ?, ?)",
        (token, user_id, now, now),
    )
    return token


def _extract_bearer_token(authorization: Optional[str]) -> str:
    raw = str(authorization or "").strip()
    if not raw.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    token = raw[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing access token.")
    return token


def require_auth_user(authorization: Optional[str] = Header(default=None)) -> AuthenticatedUser:
    token = _extract_bearer_token(authorization)
    now = datetime.utcnow().isoformat()
    with _db_connect() as conn:
        row = conn.execute(
            """
            SELECT s.token, u.id as user_id, u.username, u.is_admin
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Session expired or invalid token.")
        conn.execute(
            "UPDATE sessions SET last_seen_at = ? WHERE token = ?",
            (now, token),
        )
        return AuthenticatedUser(
            user_id=int(row["user_id"]),
            username=str(row["username"]),
            token=str(row["token"]),
            is_admin=bool(int(row["is_admin"])),
        )


def is_effective_admin(user: AuthenticatedUser) -> bool:
    if user.is_admin:
        return True
    return bool(AUTH_ADMIN_USERS and user.username.lower() in AUTH_ADMIN_USERS)


def require_admin_user(user: AuthenticatedUser = Depends(require_auth_user)) -> AuthenticatedUser:
    """
    Admin auth layer.

    Access is granted only if:
    - user has is_admin=1 in DB, OR
    - user exists in AUTH_ADMIN_USERS env allowlist.
    """
    if is_effective_admin(user):
        return user
    raise HTTPException(status_code=403, detail="Admin access denied for this account.")


def _pick_primary_model_name(model_names: Iterable[str]) -> str:
    names = set(model_names)
    for preferred in ("lightgbm", "xgboost", "random_forest"):
        if preferred in names:
            return preferred
    return sorted(names)[0]


def _safe_float(value: Any) -> Optional[float]:
    try:
        if isinstance(value, bool):
            return None
        return float(value)
    except Exception:
        return None


def _is_valid_correlation_matrix(matrix: Any) -> bool:
    if not isinstance(matrix, list) or len(matrix) < 2:
        return False
    size = len(matrix)
    for row in matrix:
        if not isinstance(row, list) or len(row) < size:
            return False
        for item in row[:size]:
            if _safe_float(item) is None:
                return False
    return True


def _normalize_confusion_matrix(confusion: Any) -> Optional[List[List[float]]]:
    if (
        not isinstance(confusion, list)
        or len(confusion) != 2
        or not isinstance(confusion[0], list)
        or not isinstance(confusion[1], list)
        or len(confusion[0]) != 2
        or len(confusion[1]) != 2
    ):
        return None

    tn = _safe_float(confusion[0][0])
    fp = _safe_float(confusion[0][1])
    fn = _safe_float(confusion[1][0])
    tp = _safe_float(confusion[1][1])
    if None in (tn, fp, fn, tp):
        return None

    return [
        [max(0.0, float(tn)), max(0.0, float(fp))],
        [max(0.0, float(fn)), max(0.0, float(tp))],
    ]


def _build_similarity_correlation(values: List[float]) -> List[List[float]]:
    if len(values) < 2:
        return []

    matrix: List[List[float]] = []
    for i, vi in enumerate(values):
        row: List[float] = []
        for j, vj in enumerate(values):
            if i == j:
                row.append(1.0)
                continue
            # Similarity in [0,1] mapped to correlation-like score in [-1,1].
            corr = 1.0 - 2.0 * min(1.0, abs(float(vi) - float(vj)))
            row.append(float(max(-1.0, min(1.0, corr))))
        matrix.append(row)
    return matrix


def _resolve_correlation_artifacts(
    model_meta: Dict[str, Any],
) -> Tuple[Optional[List[List[float]]], Optional[List[str]]]:
    existing_matrix = model_meta.get("correlation_matrix")
    existing_labels = model_meta.get("correlation_labels")
    if _is_valid_correlation_matrix(existing_matrix):
        matrix = existing_matrix  # type: ignore[assignment]
        size = len(matrix)  # type: ignore[arg-type]
        if isinstance(existing_labels, list) and len(existing_labels) >= size:
            labels = [str(item) for item in existing_labels[:size]]
        else:
            labels = [f"F{i + 1}" for i in range(size)]
        return matrix, labels

    metrics = model_meta.get("metrics")
    if isinstance(metrics, dict):
        metric_order = [
            ("accuracy", "Accuracy"),
            ("precision", "Precision"),
            ("recall", "Recall"),
            ("f1_score", "F1"),
            ("roc_auc", "ROC-AUC"),
        ]
        values: List[float] = []
        labels: List[str] = []
        for key, label in metric_order:
            value = _safe_float(metrics.get(key))
            if value is None:
                continue
            values.append(float(max(0.0, min(1.0, value))))
            labels.append(label)
        if len(values) >= 2:
            return _build_similarity_correlation(values), labels

    normalized_confusion = _normalize_confusion_matrix(model_meta.get("confusion_matrix"))
    if normalized_confusion is not None:
        tn, fp = normalized_confusion[0]
        fn, tp = normalized_confusion[1]
        total = tn + fp + fn + tp
        if total > 0:
            values = [tn / total, fp / total, fn / total, tp / total]
            labels = ["TN share", "FP share", "FN share", "TP share"]
            return _build_similarity_correlation(values), labels

    return None, None


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


@app.post("/auth/register", response_model=AuthResponse)
async def auth_register(payload: AuthRequest):
    username = _normalize_username(payload.username)
    password = _validate_password(payload.password)
    salt_hex = secrets.token_hex(16)
    password_hash = _hash_password(password, salt_hex)
    now = datetime.utcnow().isoformat()

    with _db_connect() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if existing is not None:
            raise HTTPException(status_code=409, detail="Username already exists.")

        users_count = int(conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"])
        admin_count = int(
            conn.execute("SELECT COUNT(*) AS count FROM users WHERE is_admin = 1").fetchone()["count"]
        )
        is_admin = users_count == 0 or admin_count == 0

        cursor = conn.execute(
            """
            INSERT INTO users(username, password_hash, salt, created_at, is_admin)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, password_hash, salt_hex, now, 1 if is_admin else 0),
        )
        user_id = int(cursor.lastrowid)
        token = _create_session(conn, user_id)

    return AuthResponse(token=token, username=username, is_admin=is_admin)


@app.post("/auth/login", response_model=AuthResponse)
async def auth_login(payload: AuthRequest):
    username = _normalize_username(payload.username)
    password = _validate_password(payload.password)

    with _db_connect() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, salt, is_admin FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        expected_hash = str(row["password_hash"])
        actual_hash = _hash_password(password, str(row["salt"]))
        if not hmac.compare_digest(expected_hash, actual_hash):
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        user_id = int(row["id"])
        token = _create_session(conn, user_id)
        auth_user = AuthenticatedUser(
            user_id=user_id,
            username=str(row["username"]),
            token=token,
            is_admin=bool(int(row["is_admin"])),
        )
        return AuthResponse(
            token=token,
            username=auth_user.username,
            is_admin=is_effective_admin(auth_user),
        )


@app.get("/auth/me")
async def auth_me(user: AuthenticatedUser = Depends(require_auth_user)):
    return {
        "username": user.username,
        "authenticated": True,
        "is_admin": is_effective_admin(user),
    }


@app.post("/auth/logout")
async def auth_logout(user: AuthenticatedUser = Depends(require_auth_user)):
    with _db_connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (user.token,))
    return {"success": True}


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
async def predict_file(
    file: UploadFile = File(...),
    _user: AuthenticatedUser = Depends(require_auth_user),
):
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
async def predict_url(
    request: URLPredictionRequest,
    _user: AuthenticatedUser = Depends(require_auth_user),
):
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
    _user: AuthenticatedUser = Depends(require_auth_user),
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
async def model_info(_user: AuthenticatedUser = Depends(require_auth_user)):
    model = require_model()
    meta = model.metadata

    metrics = meta.get("metrics", {}) if isinstance(meta.get("metrics"), dict) else {}
    loaded_models: Dict[str, Dict[str, Any]] = {}
    for model_name, model_obj in runtime_predict_models.items():
        model_meta = model_obj.metadata if isinstance(model_obj.metadata, dict) else {}
        corr_matrix, corr_labels = _resolve_correlation_artifacts(model_meta)
        loaded_models[model_name] = {
            "model_name": model_name,
            "model_type": model_meta.get("model_type", model_obj.__class__.__name__),
            "model_path": str(model_obj.model_path),
            "input_features": int(model_obj.feature_count),
            "threshold": float(model_obj.threshold),
            "metrics": model_meta.get("metrics"),
            "confusion_matrix": model_meta.get("confusion_matrix"),
            "roc_curve_points": model_meta.get("roc_curve_points"),
            "correlation_matrix": corr_matrix,
            "correlation_labels": corr_labels,
            "training_samples": model_meta.get("training_samples"),
            "test_samples": model_meta.get("test_samples"),
            "created_at": model_meta.get("created_at"),
            "notes": model_meta.get("notes"),
            "training_info": model_meta.get("training_info"),
            "bootstrap_generated": bool(model_meta.get("bootstrap_generated")),
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
        url_corr_matrix, url_corr_labels = _resolve_correlation_artifacts(url_meta)
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
            "correlation_matrix": url_corr_matrix,
            "correlation_labels": url_corr_labels,
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

    top_corr_matrix, top_corr_labels = _resolve_correlation_artifacts(meta)

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
        "correlation_matrix": top_corr_matrix,
        "correlation_labels": top_corr_labels,
        "created_at": meta.get("created_at"),
        "notes": meta.get("notes"),
        "bodmas_included": meta.get("bodmas_included"),
        "training_info": meta.get("training_info"),
        "frontend_build_available": frontend_build_available(),
        "frontend_app_path": "/app" if frontend_build_available() else None,
    }


@app.get("/frontend-status")
async def frontend_status(_user: AuthenticatedUser = Depends(require_auth_user)):
    return {
        "frontend_build_available": frontend_build_available(),
        "frontend_build_dir": str(FRONTEND_BUILD_DIR),
        "frontend_index_file": str(FRONTEND_INDEX_FILE),
        "frontend_app_path": "/app" if frontend_build_available() else None,
    }


@app.get("/admin")
async def admin_endpoint(user: AuthenticatedUser = Depends(require_admin_user)):
    with _db_connect() as conn:
        users_count = int(conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"])
        sessions_count = int(conn.execute("SELECT COUNT(*) AS count FROM sessions").fetchone()["count"])

    return {
        "admin_user": user.username,
        "is_admin": is_effective_admin(user),
        "auth_admin_users_configured": sorted(AUTH_ADMIN_USERS),
        "users_count": users_count,
        "active_sessions_count": sessions_count,
        "loaded_prediction_models": sorted(runtime_predict_models.keys()),
        "unavailable_prediction_models": dict(runtime_unavailable_models),
        "url_model_loaded": runtime_url_model is not None,
        "frontend_build_available": frontend_build_available(),
        "timestamp": datetime.now().isoformat(),
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
