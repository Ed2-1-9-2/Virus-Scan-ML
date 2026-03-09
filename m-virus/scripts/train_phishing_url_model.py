"""Train URL phishing detector on phishing-dataset JSON files."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _label_counts(labels: np.ndarray) -> Dict[int, int]:
    unique, counts = np.unique(labels, return_counts=True)
    return {int(k): int(v) for k, v in zip(unique, counts)}


def _balanced_choice(labels: np.ndarray, max_samples: int, seed: int) -> np.ndarray:
    if max_samples <= 0 or len(labels) <= max_samples:
        return np.arange(len(labels))

    rng = np.random.default_rng(seed)
    idx0 = np.flatnonzero(labels == 0)
    idx1 = np.flatnonzero(labels == 1)
    if len(idx0) == 0 or len(idx1) == 0:
        return rng.choice(len(labels), size=max_samples, replace=False)

    per_class = max_samples // 2
    take0 = min(per_class, len(idx0))
    take1 = min(per_class, len(idx1))

    chosen0 = rng.choice(idx0, size=take0, replace=False)
    chosen1 = rng.choice(idx1, size=take1, replace=False)
    chosen = np.concatenate([chosen0, chosen1], axis=0)

    remaining = max_samples - len(chosen)
    if remaining > 0:
        pool = np.setdiff1d(np.arange(len(labels)), chosen, assume_unique=False)
        if len(pool) > 0:
            extra = rng.choice(pool, size=min(remaining, len(pool)), replace=False)
            chosen = np.concatenate([chosen, extra], axis=0)

    rng.shuffle(chosen)
    return chosen


def normalize_url(url: str) -> str:
    value = (url or "").strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = f"http://{value}"
    return value


def load_dataset_records(dataset_path: Path) -> Tuple[List[str], np.ndarray]:
    with dataset_path.open("r", encoding="utf-8-sig") as handle:
        data = json.load(handle)

    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected dataset format in {dataset_path}. Expected a JSON list.")

    texts: List[str] = []
    labels: List[int] = []
    dropped = 0
    for sample in data:
        if not isinstance(sample, dict):
            dropped += 1
            continue
        text = normalize_url(str(sample.get("text", "")))
        if not text:
            dropped += 1
            continue

        raw_label = sample.get("label")
        try:
            label = int(raw_label)
        except Exception:
            dropped += 1
            continue

        if label not in (0, 1):
            dropped += 1
            continue

        texts.append(text)
        labels.append(label)

    if not texts:
        raise RuntimeError(f"No valid samples loaded from {dataset_path}")

    y = np.asarray(labels, dtype=np.int32)
    print(
        f"Loaded dataset: samples={len(texts)} labels={_label_counts(y)} dropped_invalid={dropped}"
    )
    return texts, y


def evaluate(y_true: np.ndarray, y_proba: np.ndarray, threshold: float) -> Dict:
    y_pred = (y_proba >= threshold).astype(np.int32)
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_proba)),
        "threshold": float(threshold),
    }
    cm = confusion_matrix(y_true, y_pred)
    print("\nEvaluation")
    print("=" * 70)
    print(f"Accuracy : {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall   : {metrics['recall']:.4f}")
    print(f"F1-score : {metrics['f1_score']:.4f}")
    print(f"ROC-AUC  : {metrics['roc_auc']:.4f}")
    print("\nConfusion matrix:")
    print(cm)
    fpr, tpr, _ = roc_curve(y_true, y_proba)
    return {
        "metrics": metrics,
        "confusion_matrix": cm.tolist(),
        "roc_curve_points": [[float(x), float(y)] for x, y in zip(fpr.tolist(), tpr.tolist())],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train URL phishing model on phishing-dataset JSON files."
    )
    parser.add_argument(
        "--dataset-path",
        type=str,
        default=str(PROJECT_ROOT / "phishing-dataset" / "urls.json"),
        help="Path to phishing dataset JSON file (records with text,label).",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=0,
        help="Max samples to use (0=all).",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test split ratio.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Classification threshold.",
    )
    parser.add_argument(
        "--n-features",
        type=int,
        default=2**20,
        help="HashingVectorizer feature size.",
    )
    parser.add_argument(
        "--alpha",
        type=float,
        default=1e-6,
        help="SGD regularization alpha.",
    )
    parser.add_argument(
        "--max-iter",
        type=int,
        default=30,
        help="SGD max iterations.",
    )
    parser.add_argument(
        "--model-out",
        type=str,
        default=str(PROJECT_ROOT / "models" / "url_phishing_model.joblib"),
        help="Output path for model artifact.",
    )
    parser.add_argument(
        "--metadata-out",
        type=str,
        default=str(PROJECT_ROOT / "models" / "url_phishing_model_metadata.json"),
        help="Output path for metadata JSON.",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset_path)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    print("=" * 70)
    print("URL PHISHING MODEL TRAINING")
    print("=" * 70)
    print(f"Dataset path : {dataset_path}")
    print(f"Max samples  : {args.max_samples}")
    print(f"Test size    : {args.test_size}")

    texts, labels = load_dataset_records(dataset_path)

    if args.max_samples and args.max_samples > 0 and len(labels) > args.max_samples:
        picked = _balanced_choice(labels, max_samples=args.max_samples, seed=args.seed)
        texts = [texts[i] for i in picked]
        labels = labels[picked]
        print(f"After sampling: samples={len(texts)} labels={_label_counts(labels)}")

    train_texts, test_texts, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=labels,
    )
    print(
        f"Train split: samples={len(train_texts)} labels={_label_counts(y_train)} | "
        f"Test split: samples={len(test_texts)} labels={_label_counts(y_test)}"
    )

    vectorizer = HashingVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        n_features=int(args.n_features),
        lowercase=True,
        alternate_sign=False,
        norm="l2",
    )
    classifier = SGDClassifier(
        loss="log_loss",
        alpha=float(args.alpha),
        max_iter=int(args.max_iter),
        tol=1e-3,
        random_state=int(args.seed),
        class_weight="balanced",
        early_stopping=True,
        n_iter_no_change=5,
    )

    X_train = vectorizer.transform(train_texts)
    X_test = vectorizer.transform(test_texts)

    print("Training classifier...")
    classifier.fit(X_train, y_train)

    y_proba = classifier.predict_proba(X_test)[:, 1].astype(np.float32)
    evaluation = evaluate(y_test, y_proba, threshold=float(args.threshold))

    model_out = Path(args.model_out)
    metadata_out = Path(args.metadata_out)
    model_out.parent.mkdir(parents=True, exist_ok=True)
    metadata_out.parent.mkdir(parents=True, exist_ok=True)

    try:
        from joblib import dump as joblib_dump  # type: ignore
    except Exception as exc:
        raise RuntimeError("joblib is required to save URL model artifact.") from exc

    artifact = {
        "model_type": "URL Phishing Hashing+SGD (log_loss)",
        "created_at": datetime.now().isoformat(),
        "vectorizer": vectorizer,
        "classifier": classifier,
        "threshold": float(args.threshold),
        "input_features": int(args.n_features),
    }
    joblib_dump(artifact, model_out)

    metadata = {
        "model_type": artifact["model_type"],
        "created_at": artifact["created_at"],
        "threshold": float(args.threshold),
        "input_features": int(args.n_features),
        "training_samples": int(len(train_texts)),
        "test_samples": int(len(test_texts)),
        "dataset_path": str(dataset_path),
        "dataset_total_samples": int(len(texts)),
        "metrics": evaluation["metrics"],
        "confusion_matrix": evaluation["confusion_matrix"],
        "roc_curve_points": evaluation.get("roc_curve_points", []),
        "notes": "Trained on phishing-dataset JSON text/label records; designed for URL string inference.",
        "training_info": {
            "vectorizer": "HashingVectorizer(char, 3-5)",
            "classifier": "SGDClassifier(log_loss, class_weight=balanced)",
            "alpha": float(args.alpha),
            "max_iter": int(args.max_iter),
            "seed": int(args.seed),
            "sampled": bool(args.max_samples and args.max_samples > 0),
        },
    }
    metadata_out.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"\nModel saved to: {model_out}")
    print(f"Metadata saved to: {metadata_out}")


if __name__ == "__main__":
    main()
