"""Shared utilities for malware model inference and feature handling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence

import numpy as np
import xgboost as xgb

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

        meta_threshold = self.metadata.get("threshold")
        if threshold is not None:
            self.threshold = float(threshold)
        elif isinstance(meta_threshold, (int, float)):
            self.threshold = float(meta_threshold)
        else:
            self.threshold = 0.5

    def predict_one(self, features: Sequence[float], sha256: Optional[str] = None) -> Dict[str, Any]:
        arr = normalize_features(features, self.feature_count).reshape(1, -1)
        proba = float(self.model.predict(xgb.DMatrix(arr))[0])
        prediction = "Malware" if proba >= self.threshold else "Benign"

        return {
            "prediction": prediction,
            "probability_malware": proba,
            "confidence": float(max(proba, 1.0 - proba)),
            "sha256": sha256,
        }

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


__all__ = [
    "DEFAULT_METADATA_PATH",
    "DEFAULT_MODEL_PATH",
    "EMBER_CATEGORIES",
    "XGBoostMalwareModel",
    "flatten_ember_features",
    "iter_jsonl_records",
    "load_metadata",
    "normalize_features",
]
