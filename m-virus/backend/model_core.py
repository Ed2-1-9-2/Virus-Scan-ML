"""Shared utilities for malware model inference and feature handling."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence
from urllib.parse import urlparse

import numpy as np
import xgboost as xgb

from backend.explainability import (
    GLOBAL_EXPLAIN_TOP_N,
    LOCAL_EXPLAIN_TOP_N,
    build_feature_names,
    build_feature_space_note,
    build_unavailable_explainability,
    random_forest_local_contributions,
    summarize_global_importance,
    summarize_local_contributions,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "xgboost_malware_model.json"
DEFAULT_METADATA_PATH = PROJECT_ROOT / "models" / "model_metadata.json"

# Keep category ordering aligned with the existing training/inference pipeline.
EMBER_CATEGORIES: Sequence[str] = (
    "histogram",
    "byteentropy",
    "strings",
    "general",
    "header",
    "section",
    "imports",
    "exports",
)


def flatten_ember_features(record: Dict[str, Any]) -> np.ndarray:
    """
    Flatten EMBER-style JSON object into a feature vector.

    This intentionally preserves the legacy extraction behavior used by the
    existing scripts so loaded models remain compatible.
    """
    feature_list: List[float] = []

    for category in EMBER_CATEGORIES:
        if category in record and isinstance(record[category], dict):
            for _, value in record[category].items():
                if isinstance(value, (int, float)):
                    feature_list.append(float(value))
                elif isinstance(value, list):
                    feature_list.extend(
                        float(v) for v in value if isinstance(v, (int, float))
                    )
        elif category in record and isinstance(record[category], list):
            feature_list.extend(
                float(v) for v in record[category] if isinstance(v, (int, float))
            )

    return np.asarray(feature_list, dtype=np.float32)


def normalize_features(features: Sequence[float], expected_length: int) -> np.ndarray:
    """Pad or truncate features to model input length."""
    arr = np.asarray(features, dtype=np.float32).reshape(-1)

    if arr.size < expected_length:
        arr = np.pad(arr, (0, expected_length - arr.size), mode="constant")
    elif arr.size > expected_length:
        arr = arr[:expected_length]

    return arr


def iter_jsonl_records(path: Path) -> Iterator[Dict[str, Any]]:
    """Yield parsed JSON objects from a JSONL file."""
    with path.open("r", encoding="utf-8-sig") as handle:
        for lineno, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at line {lineno}: {exc}") from exc


def load_metadata(metadata_path: Path) -> Dict[str, Any]:
    """Load metadata if present, otherwise return empty dict."""
    if not metadata_path.exists():
        return {}

    try:
        with metadata_path.open("r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def read_git_lfs_pointer(path: Path) -> Optional[Dict[str, str]]:
    """Return parsed Git LFS pointer info when file is an LFS stub, else None."""
    if not path.exists() or not path.is_file():
        return None

    try:
        raw = path.read_text(encoding="utf-8")
    except Exception:
        return None

    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines or lines[0] != "version https://git-lfs.github.com/spec/v1":
        return None

    payload: Dict[str, str] = {}
    for line in lines[1:]:
        if " " not in line:
            continue
        key, value = line.split(" ", 1)
        payload[key.strip()] = value.strip()
    return payload


def _prepare_lightgbm_model_file(model_path: Path) -> Path:
    """
    Return a LightGBM model path safe for runtime loading.

    Large LightGBM text models can fail to parse when checked out with CRLF
    line endings on Windows. When CRLF is detected, write an LF-normalized
    runtime copy and load that copy instead.
    """
    try:
        raw = model_path.read_bytes()
    except Exception:
        return model_path

    if b"\r\n" not in raw:
        return model_path

    normalized_raw = raw.replace(b"\r\n", b"\n")
    normalized_path = model_path.with_suffix(model_path.suffix + ".lf")

    try:
        if not normalized_path.exists() or normalized_path.read_bytes() != normalized_raw:
            normalized_path.write_bytes(normalized_raw)
        return normalized_path
    except Exception:
        # If normalization fails (permissions/disk), fallback to original path.
        return model_path

def _resolve_threshold(
    metadata: Dict[str, Any],
    threshold: Optional[float] = None,
    default: float = 0.5,
) -> float:
    meta_threshold = metadata.get("threshold")
    if threshold is not None:
        return float(threshold)
    if isinstance(meta_threshold, (int, float)):
        return float(meta_threshold)
    return float(default)


def _build_binary_prediction(proba: float, threshold: float, sha256: Optional[str]) -> Dict[str, Any]:
    prediction = "Malware" if proba >= threshold else "Benign"
    return {
        "prediction": prediction,
        "probability_malware": proba,
        "confidence": float(max(proba, 1.0 - proba)),
        "sha256": sha256,
    }


def _prepare_numpy_joblib_compat() -> None:
    """
    Provide compatibility aliases for joblib artifacts serialized with newer NumPy.

    Some artifacts reference private module paths like `numpy._core.*`.
    On older NumPy runtimes these modules do not exist; we alias them to
    available `numpy.core.*` modules so unpickling can proceed.
    """
    try:
        import numpy.core as npcore  # type: ignore
    except Exception:
        return

    sys.modules.setdefault("numpy._core", npcore)
    for submodule in ("multiarray", "numeric", "_multiarray_umath"):
        target = getattr(npcore, submodule, None)
        if target is not None:
            sys.modules.setdefault(f"numpy._core.{submodule}", target)


def normalize_url_text(url: str) -> str:
    value = (url or "").strip()
    if not value:
        raise ValueError("URL is empty")

    if "://" not in value:
        value = f"http://{value}"

    parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError("URL is invalid")

    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{scheme}://{netloc}{path}{query}{fragment}"


class XGBoostMalwareModel:
    """Runtime wrapper around an XGBoost malware classifier."""

    def __init__(
        self,
        model_path: Path | str = DEFAULT_MODEL_PATH,
        metadata_path: Path | str = DEFAULT_METADATA_PATH,
        threshold: Optional[float] = None,
    ) -> None:
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)

        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")

        self.model = xgb.Booster()
        self.model.load_model(str(self.model_path))

        self.metadata = load_metadata(self.metadata_path)
        self.feature_count = int(self.model.num_features())
        self.feature_names = build_feature_names(self.metadata, self.feature_count)
        self.feature_space_note = build_feature_space_note(self.metadata, self.feature_count)

        self.threshold = _resolve_threshold(self.metadata, threshold=threshold, default=0.5)

    def predict_one(self, features: Sequence[float], sha256: Optional[str] = None) -> Dict[str, Any]:
        arr = normalize_features(features, self.feature_count).reshape(1, -1)
        proba = float(self.model.predict(xgb.DMatrix(arr))[0])
        return _build_binary_prediction(proba=proba, threshold=self.threshold, sha256=sha256)

    def predict_batch(self, embeddings: Sequence[Sequence[float]]) -> Dict[str, np.ndarray]:
        matrix = np.asarray(embeddings, dtype=np.float32)
        if matrix.ndim == 1:
            matrix = matrix.reshape(1, -1)

        normalized = np.stack(
            [normalize_features(row, self.feature_count) for row in matrix], axis=0
        )

        probas = self.model.predict(xgb.DMatrix(normalized)).astype(np.float32)
        predictions = (probas >= self.threshold).astype(np.int32)
        confidences = np.maximum(probas, 1.0 - probas)

        return {
            "predictions": predictions,
            "probabilities": probas,
            "confidences": confidences.astype(np.float32),
            "normalized_embeddings": normalized,
        }

    def get_global_explainability(self, top_n: int = GLOBAL_EXPLAIN_TOP_N) -> Dict[str, Any]:
        try:
            score_map = self.model.get_score(importance_type="gain")
            importances = np.zeros(self.feature_count, dtype=np.float64)
            for key, value in score_map.items():
                if not str(key).startswith("f"):
                    continue
                try:
                    index = int(str(key)[1:])
                except Exception:
                    continue
                if 0 <= index < self.feature_count:
                    importances[index] = float(value)

            summary = summarize_global_importance(importances, self.feature_names, top_n=top_n)
            summary.update(
                {
                    "available": True,
                    "supports_local": True,
                    "supports_global": True,
                    "local_method": "xgboost_pred_contribs",
                    "global_method": "xgboost_gain_importance",
                    "contribution_space": "raw_model_score",
                    "feature_space_note": self.feature_space_note,
                    "note": (
                        "Local contributions come from XGBoost pred_contribs and are additive in raw model score space, "
                        "not direct probability points."
                    ),
                }
            )
            return summary
        except Exception as exc:
            return build_unavailable_explainability(
                note=f"Explainable AI is unavailable for this XGBoost model: {exc}",
                local_method="xgboost_pred_contribs",
                global_method="xgboost_gain_importance",
                feature_space_note=self.feature_space_note,
            )

    def explain_one(
        self,
        features: Sequence[float],
        sha256: Optional[str] = None,
        top_n: int = LOCAL_EXPLAIN_TOP_N,
    ) -> Dict[str, Any]:
        arr = normalize_features(features, self.feature_count).reshape(1, -1)
        dmatrix = xgb.DMatrix(arr)
        proba = float(self.model.predict(dmatrix)[0])
        prediction = _build_binary_prediction(proba=proba, threshold=self.threshold, sha256=sha256)

        try:
            raw_contribs = np.asarray(self.model.predict(dmatrix, pred_contribs=True), dtype=np.float64)
            contribs = raw_contribs[0]
            bias = float(contribs[-1]) if contribs.size > self.feature_count else 0.0
            feature_contribs = contribs[: self.feature_count]
            summary = summarize_local_contributions(
                feature_contribs,
                arr[0],
                self.feature_names,
                top_n=top_n,
            )
            summary.update(
                {
                    "available": True,
                    "method": "xgboost_pred_contribs",
                    "contribution_space": "raw_model_score",
                    "bias": bias,
                    "feature_space_note": self.feature_space_note,
                    "note": (
                        "Positive contributions push the decision toward Malware, negative contributions toward Benign. "
                        "Values are additive in raw model score space."
                    ),
                }
            )
            prediction["explainable_ai"] = summary
        except Exception as exc:
            prediction["explainable_ai"] = build_unavailable_explainability(
                note=f"Local explainability failed for XGBoost: {exc}",
                local_method="xgboost_pred_contribs",
                feature_space_note=self.feature_space_note,
            )

        return prediction

    def predict_ember_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        sha256 = record.get("sha256")
        features = flatten_ember_features(record)
        return self.predict_one(features, sha256=sha256)

    def predict_jsonl(
        self,
        path: Path | str,
        sha256: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        target_path = Path(path)
        results: List[Dict[str, Any]] = []

        for record in iter_jsonl_records(target_path):
            record_sha = record.get("sha256")
            if sha256 and record_sha != sha256:
                continue

            result = self.predict_ember_record(record)
            results.append(result)

            if sha256:
                break
            if limit is not None and len(results) >= limit:
                break

        return results


class LightGBMMalwareModel:
    """Runtime wrapper around a LightGBM malware classifier."""

    def __init__(
        self,
        model_path: Path | str,
        metadata_path: Path | str,
        threshold: Optional[float] = None,
    ) -> None:
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)

        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")

        try:
            import lightgbm as lgb  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "LightGBM runtime dependency is missing. Install it with: pip install lightgbm"
            ) from exc

        runtime_model_path = _prepare_lightgbm_model_file(self.model_path)
        self.model = lgb.Booster(model_file=str(runtime_model_path))
        self.metadata = load_metadata(self.metadata_path)

        meta_input = self.metadata.get("input_features")
        if isinstance(meta_input, int) and meta_input > 0:
            self.feature_count = int(meta_input)
        else:
            self.feature_count = int(self.model.num_feature())
        self.feature_names = build_feature_names(self.metadata, self.feature_count)
        self.feature_space_note = build_feature_space_note(self.metadata, self.feature_count)

        self.threshold = _resolve_threshold(self.metadata, threshold=threshold, default=0.5)

    def predict_one(self, features: Sequence[float], sha256: Optional[str] = None) -> Dict[str, Any]:
        arr = normalize_features(features, self.feature_count).reshape(1, -1)
        proba = float(self.model.predict(arr)[0])
        return _build_binary_prediction(proba=proba, threshold=self.threshold, sha256=sha256)

    def get_global_explainability(self, top_n: int = GLOBAL_EXPLAIN_TOP_N) -> Dict[str, Any]:
        try:
            importances = np.asarray(
                self.model.feature_importance(importance_type="gain"),
                dtype=np.float64,
            ).reshape(-1)
            if not np.any(importances > 0):
                importances = np.asarray(
                    self.model.feature_importance(importance_type="split"),
                    dtype=np.float64,
                ).reshape(-1)

            summary = summarize_global_importance(importances, self.feature_names, top_n=top_n)
            summary.update(
                {
                    "available": True,
                    "supports_local": True,
                    "supports_global": True,
                    "local_method": "lightgbm_pred_contrib",
                    "global_method": "lightgbm_gain_importance",
                    "contribution_space": "raw_model_score",
                    "feature_space_note": self.feature_space_note,
                    "note": (
                        "Local contributions come from LightGBM pred_contrib output and are additive in raw model score space, "
                        "not direct probability points."
                    ),
                }
            )
            return summary
        except Exception as exc:
            return build_unavailable_explainability(
                note=f"Explainable AI is unavailable for this LightGBM model: {exc}",
                local_method="lightgbm_pred_contrib",
                global_method="lightgbm_gain_importance",
                feature_space_note=self.feature_space_note,
            )

    def explain_one(
        self,
        features: Sequence[float],
        sha256: Optional[str] = None,
        top_n: int = LOCAL_EXPLAIN_TOP_N,
    ) -> Dict[str, Any]:
        arr = normalize_features(features, self.feature_count).reshape(1, -1)
        proba = float(self.model.predict(arr)[0])
        prediction = _build_binary_prediction(proba=proba, threshold=self.threshold, sha256=sha256)

        try:
            raw_contribs = np.asarray(self.model.predict(arr, pred_contrib=True), dtype=np.float64)
            contribs = raw_contribs[0]
            bias = float(contribs[-1]) if contribs.size > self.feature_count else 0.0
            feature_contribs = contribs[: self.feature_count]
            summary = summarize_local_contributions(
                feature_contribs,
                arr[0],
                self.feature_names,
                top_n=top_n,
            )
            summary.update(
                {
                    "available": True,
                    "method": "lightgbm_pred_contrib",
                    "contribution_space": "raw_model_score",
                    "bias": bias,
                    "feature_space_note": self.feature_space_note,
                    "note": (
                        "Positive contributions push the decision toward Malware, negative contributions toward Benign. "
                        "Values are additive in raw model score space."
                    ),
                }
            )
            prediction["explainable_ai"] = summary
        except Exception as exc:
            prediction["explainable_ai"] = build_unavailable_explainability(
                note=f"Local explainability failed for LightGBM: {exc}",
                local_method="lightgbm_pred_contrib",
                feature_space_note=self.feature_space_note,
            )

        return prediction


class RandomForestMalwareModel:
    """Runtime wrapper around a scikit-learn RandomForest malware classifier."""

    def __init__(
        self,
        model_path: Path | str,
        metadata_path: Path | str,
        threshold: Optional[float] = None,
    ) -> None:
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)

        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")

        try:
            from joblib import load as joblib_load  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "RandomForest runtime dependency is missing. Install it with: pip install joblib scikit-learn"
            ) from exc

        pointer_info = read_git_lfs_pointer(self.model_path)
        if pointer_info is not None:
            expected_size = pointer_info.get("size", "unknown")
            oid = pointer_info.get("oid", "unknown")
            raise RuntimeError(
                "RandomForest model file is a Git LFS pointer, not the real artifact. "
                f"Expected binary size={expected_size}, oid={oid}. "
                "Download the real file from media.githubusercontent.com or run start_mvirus_fullstack.py."
            )

        _prepare_numpy_joblib_compat()
        self.model = joblib_load(self.model_path)
        self.metadata = load_metadata(self.metadata_path)
        if hasattr(self.model, "n_jobs"):
            try:
                self.model.n_jobs = 1
            except Exception:
                pass

        meta_input = self.metadata.get("input_features")
        if isinstance(meta_input, int) and meta_input > 0:
            self.feature_count = int(meta_input)
        else:
            self.feature_count = int(getattr(self.model, "n_features_in_", 0))
        if self.feature_count <= 0:
            raise RuntimeError(
                "Could not determine RandomForest input feature count from model/metadata."
            )
        self.feature_names = build_feature_names(self.metadata, self.feature_count)
        self.feature_space_note = build_feature_space_note(self.metadata, self.feature_count)

        if not hasattr(self.model, "predict_proba"):
            raise RuntimeError("RandomForest model does not expose predict_proba().")

        self.threshold = _resolve_threshold(self.metadata, threshold=threshold, default=0.5)

    def predict_one(self, features: Sequence[float], sha256: Optional[str] = None) -> Dict[str, Any]:
        arr = normalize_features(features, self.feature_count).reshape(1, -1)
        probas = self.model.predict_proba(arr)
        if probas.ndim != 2 or probas.shape[1] < 2:
            raise RuntimeError("RandomForest predict_proba output has unexpected shape.")
        proba = float(probas[0, 1])
        return _build_binary_prediction(proba=proba, threshold=self.threshold, sha256=sha256)

    def get_global_explainability(self, top_n: int = GLOBAL_EXPLAIN_TOP_N) -> Dict[str, Any]:
        try:
            importances = np.asarray(getattr(self.model, "feature_importances_", []), dtype=np.float64).reshape(-1)
            summary = summarize_global_importance(importances, self.feature_names, top_n=top_n)
            summary.update(
                {
                    "available": True,
                    "supports_local": True,
                    "supports_global": True,
                    "local_method": "random_forest_tree_path",
                    "global_method": "random_forest_feature_importances",
                    "contribution_space": "probability_delta",
                    "feature_space_note": self.feature_space_note,
                    "note": (
                        "Local contributions are reconstructed from the path taken through each tree and averaged across the forest. "
                        "They approximate probability deltas toward Malware or Benign."
                    ),
                }
            )
            return summary
        except Exception as exc:
            return build_unavailable_explainability(
                note=f"Explainable AI is unavailable for this Random Forest model: {exc}",
                local_method="random_forest_tree_path",
                global_method="random_forest_feature_importances",
                feature_space_note=self.feature_space_note,
            )

    def explain_one(
        self,
        features: Sequence[float],
        sha256: Optional[str] = None,
        top_n: int = LOCAL_EXPLAIN_TOP_N,
    ) -> Dict[str, Any]:
        arr = normalize_features(features, self.feature_count).reshape(1, -1)
        probas = self.model.predict_proba(arr)
        if probas.ndim != 2 or probas.shape[1] < 2:
            raise RuntimeError("RandomForest predict_proba output has unexpected shape.")
        proba = float(probas[0, 1])
        prediction = _build_binary_prediction(proba=proba, threshold=self.threshold, sha256=sha256)

        try:
            bias, contribs = random_forest_local_contributions(self.model, arr[0])
            summary = summarize_local_contributions(
                contribs,
                arr[0],
                self.feature_names,
                top_n=top_n,
            )
            summary.update(
                {
                    "available": True,
                    "method": "random_forest_tree_path",
                    "contribution_space": "probability_delta",
                    "bias": float(bias),
                    "feature_space_note": self.feature_space_note,
                    "note": (
                        "Positive contributions increase the malware probability, negative contributions decrease it. "
                        "Values are averaged over the trees in the forest."
                    ),
                }
            )
            prediction["explainable_ai"] = summary
        except Exception as exc:
            prediction["explainable_ai"] = build_unavailable_explainability(
                note=f"Local explainability failed for Random Forest: {exc}",
                local_method="random_forest_tree_path",
                feature_space_note=self.feature_space_note,
            )

        return prediction


class URLPhishingModel:
    """Runtime wrapper for URL phishing classification model."""

    def __init__(
        self,
        model_path: Path | str,
        metadata_path: Optional[Path | str] = None,
        threshold: Optional[float] = None,
    ) -> None:
        self.model_path = Path(model_path)
        if metadata_path is not None:
            self.metadata_path = Path(metadata_path)
        else:
            self.metadata_path = self.model_path.with_name(f"{self.model_path.stem}_metadata.json")

        if not self.model_path.exists():
            raise FileNotFoundError(f"URL model file not found: {self.model_path}")

        try:
            from joblib import load as joblib_load  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "URL model runtime dependency missing. Install with: pip install joblib scikit-learn"
            ) from exc

        artifact = joblib_load(self.model_path)
        if not isinstance(artifact, dict):
            raise RuntimeError("Invalid URL phishing model artifact format (expected dict).")
        if "vectorizer" not in artifact or "classifier" not in artifact:
            raise RuntimeError("Invalid URL phishing model artifact keys (expected vectorizer/classifier).")

        self.vectorizer = artifact["vectorizer"]
        self.classifier = artifact["classifier"]
        self.model_type = str(artifact.get("model_type", "URL Phishing Classifier"))
        self.created_at = artifact.get("created_at")

        self.metadata = load_metadata(self.metadata_path)
        self.threshold = _resolve_threshold(self.metadata, threshold=threshold, default=0.5)

        vector_features = getattr(self.vectorizer, "n_features", None)
        meta_features = self.metadata.get("input_features")
        if isinstance(meta_features, int) and meta_features > 0:
            self.feature_count = int(meta_features)
        elif isinstance(vector_features, int) and vector_features > 0:
            self.feature_count = int(vector_features)
        else:
            self.feature_count = 0

    def get_global_explainability(self, top_n: int = GLOBAL_EXPLAIN_TOP_N) -> Dict[str, Any]:
        _ = top_n
        return build_unavailable_explainability(
            note=(
                "This URL model uses HashingVectorizer character n-grams. The hashing step prevents stable recovery of human-readable feature names, "
                "so the app does not expose exact global feature importance for it."
            ),
            feature_space_note=(
                "URL inference relies on hashed character n-grams instead of named lexical features."
            ),
        )

    def predict_one(self, url: str) -> Dict[str, Any]:
        normalized_url = normalize_url_text(url)
        matrix = self.vectorizer.transform([normalized_url])

        if hasattr(self.classifier, "predict_proba"):
            probas = self.classifier.predict_proba(matrix)
            if probas.ndim != 2 or probas.shape[1] < 2:
                raise RuntimeError("URL model predict_proba output has unexpected shape.")
            proba = float(probas[0, 1])
        elif hasattr(self.classifier, "decision_function"):
            score = float(self.classifier.decision_function(matrix)[0])
            proba = float(1.0 / (1.0 + np.exp(-score)))
        else:
            raise RuntimeError("URL model does not support probability inference.")

        prediction = "Phishing" if proba >= self.threshold else "Legitimate"
        confidence = float(max(proba, 1.0 - proba))

        return {
            "url": url,
            "normalized_url": normalized_url,
            "prediction": prediction,
            "probability_phishing": proba,
            "confidence": confidence,
            "threshold": float(self.threshold),
            "model_type": self.model_type,
            "created_at": self.metadata.get("created_at", self.created_at or datetime.now().isoformat()),
        }


__all__ = [
    "DEFAULT_METADATA_PATH",
    "DEFAULT_MODEL_PATH",
    "EMBER_CATEGORIES",
    "LightGBMMalwareModel",
    "RandomForestMalwareModel",
    "URLPhishingModel",
    "XGBoostMalwareModel",
    "flatten_ember_features",
    "iter_jsonl_records",
    "load_metadata",
    "normalize_url_text",
    "normalize_features",
]
