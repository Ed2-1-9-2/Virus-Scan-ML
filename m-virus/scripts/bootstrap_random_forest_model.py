"""Create a fallback RandomForest model artifact when no trained file is available.

This script is intended for launcher bootstrap only, so the comparative API can
load a RandomForest model out of the box from a plain GitHub ZIP checkout.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split


def _load_input_features(metadata_path: Path, fallback: int) -> int:
    if not metadata_path.exists():
        return fallback

    try:
        with metadata_path.open("r", encoding="utf-8-sig") as handle:
            payload = json.load(handle)
    except Exception:
        return fallback

    if isinstance(payload, dict):
        value = payload.get("input_features")
        if isinstance(value, int) and value > 0:
            return value
    return fallback


def _build_synthetic_dataset(feature_count: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    sample_count = 1600
    half = sample_count // 2

    # Create two separable classes with mild overlap for stable probabilities.
    benign = rng.normal(loc=0.0, scale=0.45, size=(half, feature_count)).astype(np.float32)
    malware = rng.normal(loc=0.55, scale=0.55, size=(sample_count - half, feature_count)).astype(
        np.float32
    )
    x = np.vstack([benign, malware])
    y = np.concatenate(
        [
            np.zeros(half, dtype=np.int32),
            np.ones(sample_count - half, dtype=np.int32),
        ]
    )

    indices = rng.permutation(sample_count)
    return x[indices], y[indices]


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
            corr = 1.0 - 2.0 * min(1.0, abs(float(vi) - float(vj)))
            row.append(float(max(-1.0, min(1.0, corr))))
        matrix.append(row)
    return matrix


def _evaluate_model(
    model: RandomForestClassifier,
    x_test: np.ndarray,
    y_test: np.ndarray,
    threshold: float = 0.5,
) -> Dict:
    y_proba = model.predict_proba(x_test)[:, 1].astype(np.float32)
    y_pred = (y_proba >= threshold).astype(np.int32)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_proba)),
        "threshold": float(threshold),
    }
    cm = confusion_matrix(y_test, y_pred).tolist()
    fpr, tpr, _thresholds = roc_curve(y_test, y_proba)
    roc_curve_points = [[float(x), float(y)] for x, y in zip(fpr.tolist(), tpr.tolist())]

    metric_labels = ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]
    metric_values = [
        metrics["accuracy"],
        metrics["precision"],
        metrics["recall"],
        metrics["f1_score"],
        metrics["roc_auc"],
    ]
    corr_matrix = _build_similarity_correlation(metric_values)

    return {
        "metrics": metrics,
        "confusion_matrix": cm,
        "roc_curve_points": roc_curve_points,
        "correlation_matrix": corr_matrix,
        "correlation_labels": metric_labels,
    }


def _write_metadata(
    metadata_path: Path,
    feature_count: int,
    train_samples: int,
    test_samples: int,
    evaluation: Dict,
) -> None:
    payload = {
        "model_type": "RandomForest Binary Classifier",
        "created_at": datetime.now().isoformat(),
        "threshold": 0.5,
        "input_features": int(feature_count),
        "training_samples": int(train_samples),
        "test_samples": int(test_samples),
        "metrics": evaluation.get("metrics"),
        "confusion_matrix": evaluation.get("confusion_matrix"),
        "roc_curve_points": evaluation.get("roc_curve_points"),
        "correlation_matrix": evaluation.get("correlation_matrix"),
        "correlation_labels": evaluation.get("correlation_labels"),
        "notes": (
            "Bootstrap-generated fallback model for portable launcher startup. "
            "Replace with a properly trained artifact for production quality."
        ),
        "bootstrap_generated": True,
    }
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    with metadata_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create fallback RandomForest model artifact.")
    parser.add_argument(
        "--model-out",
        default="models/random_forest_malware_model.joblib",
        help="Output path for RandomForest .joblib artifact",
    )
    parser.add_argument(
        "--metadata-path",
        default="models/random_forest_model_metadata.json",
        help="Metadata JSON used for input_features and for writing fallback metadata",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--default-features",
        type=int,
        default=2381,
        help="Fallback feature count when metadata is missing",
    )
    args = parser.parse_args()

    model_out = Path(args.model_out)
    metadata_path = Path(args.metadata_path)
    feature_count = _load_input_features(metadata_path, fallback=args.default_features)
    if feature_count <= 0:
        feature_count = int(args.default_features)

    x, y = _build_synthetic_dataset(feature_count=feature_count, seed=args.seed)
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=args.seed,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=240,
        max_depth=24,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=1,
        random_state=args.seed,
    )
    model.fit(x_train, y_train)
    evaluation = _evaluate_model(model=model, x_test=x_test, y_test=y_test, threshold=0.5)

    model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_out)
    _write_metadata(
        metadata_path=metadata_path,
        feature_count=feature_count,
        train_samples=len(y_train),
        test_samples=len(y_test),
        evaluation=evaluation,
    )

    print(f"Fallback RandomForest model saved to: {model_out}")
    print(f"Metadata written to: {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
