"""Explainability helpers for model-level and prediction-level summaries."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np


LOCAL_EXPLAIN_TOP_N = 8
GLOBAL_EXPLAIN_TOP_N = 12
_EPS = 1e-12


def _base_ember_feature_names() -> List[str]:
    names: List[str] = []
    names.extend(f"ember.histogram.byte_{idx:03d}" for idx in range(256))
    names.extend(f"ember.byteentropy.bin_{idx:03d}" for idx in range(256))
    names.append("ember.strings.numstrings")
    names.append("ember.strings.avlength")
    names.extend(f"ember.strings.printabledist_{idx:02d}" for idx in range(96))
    names.extend(
        [
            "ember.strings.printables",
            "ember.strings.entropy",
            "ember.strings.paths",
            "ember.strings.urls",
            "ember.strings.registry",
            "ember.strings.MZ",
        ]
    )
    names.extend(
        [
            "ember.general.size",
            "ember.general.vsize",
            "ember.general.has_debug",
            "ember.general.exports",
            "ember.general.imports",
            "ember.general.has_relocations",
            "ember.general.has_resources",
            "ember.general.has_signature",
            "ember.general.has_tls",
            "ember.general.symbols",
        ]
    )
    return names


def _fit_names(base: Sequence[str], expected_count: int, prefix: str) -> List[str]:
    fitted = list(base[:expected_count])
    if len(fitted) < expected_count:
        start = len(fitted)
        fitted.extend(f"{prefix}.{idx:04d}" for idx in range(start, expected_count))
    return fitted


def _generic_feature_name(prefix: str, idx: int) -> str:
    return f"{prefix}.{idx + 1:04d}"


def _feature_group(name: str) -> str:
    parts = str(name or "").split(".")
    if not parts:
        return "feature"
    if len(parts) == 1:
        return parts[0]
    return ".".join(parts[:2])


def build_feature_space_note(metadata: Dict[str, Any], feature_count: int) -> Optional[str]:
    info = metadata.get("training_info")
    if not isinstance(info, dict):
        return None

    mode = str(info.get("feature_space_mode") or "")
    ember_dim = int(info.get("ember_features") or 0)
    ember2024_dim = int(info.get("ember2024_features") or 0)
    bodmas_dim = int(info.get("bodmas_features") or 0)
    domain_flags = info.get("domain_flags") if isinstance(info.get("domain_flags"), dict) else {}

    if mode == "separate_blocks_multi_domain":
        parts = [
            f"Feature space uses separate blocks inside {feature_count} dimensions.",
            f"EMBER runtime block: {ember_dim or 'unknown'} features.",
        ]
        if ember2024_dim > 0:
            parts.append(f"EMBER2024 block: {ember2024_dim} features.")
        if bodmas_dim > 0:
            parts.append(f"BODMAS block: {bodmas_dim} features.")
        if domain_flags:
            parts.append(
                "Domain flags: "
                + ", ".join(f"{name}@{index}" for name, index in sorted(domain_flags.items(), key=lambda item: int(item[1])))
                + "."
            )
        parts.append(
            "PE runtime inference fills the legacy EMBER-compatible block first; the dataset-specific blocks remain zero-filled."
        )
        return " ".join(parts)

    if mode == "ember_only" or feature_count <= len(_base_ember_feature_names()):
        return (
            "Explainability maps the legacy EMBER-compatible feature vector used during PE runtime inference."
        )

    return None


def build_feature_names(metadata: Dict[str, Any], feature_count: int) -> List[str]:
    feature_count = max(int(feature_count), 0)
    if feature_count == 0:
        return []

    ember_names = _base_ember_feature_names()
    info = metadata.get("training_info") if isinstance(metadata.get("training_info"), dict) else {}
    mode = str(info.get("feature_space_mode") or "")

    names = [f"feature.{idx + 1:04d}" for idx in range(feature_count)]

    if mode == "separate_blocks_multi_domain":
        ember_dim = max(0, min(feature_count, int(info.get("ember_features") or len(ember_names))))
        ember_block = _fit_names(ember_names, ember_dim, prefix="ember.extra")
        names[:ember_dim] = ember_block

        cursor = ember_dim
        ember2024_dim = max(0, min(feature_count - cursor, int(info.get("ember2024_features") or 0)))
        for idx in range(ember2024_dim):
            names[cursor + idx] = _generic_feature_name("ember2024.feature", idx)
        cursor += ember2024_dim

        bodmas_dim = max(0, min(feature_count - cursor, int(info.get("bodmas_features") or 0)))
        for idx in range(bodmas_dim):
            names[cursor + idx] = _generic_feature_name("bodmas.feature", idx)

        domain_flags = info.get("domain_flags") if isinstance(info.get("domain_flags"), dict) else {}
        for flag_name, raw_index in sorted(domain_flags.items(), key=lambda item: int(item[1])):
            try:
                index = int(raw_index)
            except Exception:
                continue
            if 0 <= index < feature_count:
                names[index] = f"domain_flag.{flag_name}"
        return names

    legacy_count = min(feature_count, len(ember_names))
    names[:legacy_count] = ember_names[:legacy_count]
    for idx in range(legacy_count, feature_count):
        names[idx] = _generic_feature_name("feature", idx)
    return names


def _safe_float(value: Any) -> Optional[float]:
    try:
        result = float(value)
    except Exception:
        return None
    if not np.isfinite(result):
        return None
    return result


def _build_feature_item(
    *,
    feature_index: int,
    feature_name: str,
    feature_value: Optional[float] = None,
    contribution: Optional[float] = None,
    importance: Optional[float] = None,
    normalized_importance: Optional[float] = None,
) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "feature_index": int(feature_index),
        "feature_name": str(feature_name),
        "feature_group": _feature_group(feature_name),
    }
    if feature_value is not None:
        item["feature_value"] = float(feature_value)
    if contribution is not None:
        item["contribution"] = float(contribution)
        item["direction"] = "Malware" if contribution >= 0 else "Benign"
    if importance is not None:
        item["importance"] = float(importance)
    if normalized_importance is not None:
        item["normalized_importance"] = float(normalized_importance)
    return item


def summarize_global_importance(
    importances: Sequence[float],
    feature_names: Sequence[str],
    top_n: int = GLOBAL_EXPLAIN_TOP_N,
) -> Dict[str, Any]:
    arr = np.asarray(importances, dtype=np.float64).reshape(-1)
    size = min(len(arr), len(feature_names))
    if size <= 0:
        return {
            "non_zero_features": 0,
            "top_global_features": [],
        }

    arr = np.abs(arr[:size])
    total = float(arr.sum())
    non_zero = int(np.count_nonzero(arr > _EPS))

    indices = np.argsort(arr)[::-1]
    items: List[Dict[str, Any]] = []
    for idx in indices:
        importance = float(arr[idx])
        if importance <= _EPS and items:
            break
        items.append(
            _build_feature_item(
                feature_index=int(idx),
                feature_name=feature_names[idx],
                importance=importance,
                normalized_importance=(importance / total) if total > _EPS else 0.0,
            )
        )
        if len(items) >= max(1, int(top_n)):
            break

    return {
        "non_zero_features": non_zero,
        "top_global_features": items,
    }


def summarize_local_contributions(
    contributions: Sequence[float],
    feature_values: Sequence[float],
    feature_names: Sequence[str],
    top_n: int = LOCAL_EXPLAIN_TOP_N,
) -> Dict[str, Any]:
    contrib_arr = np.asarray(contributions, dtype=np.float64).reshape(-1)
    value_arr = np.asarray(feature_values, dtype=np.float64).reshape(-1)
    size = min(len(contrib_arr), len(value_arr), len(feature_names))
    if size <= 0:
        return {
            "non_zero_contributions": 0,
            "top_features": [],
        }

    contrib_arr = contrib_arr[:size]
    value_arr = value_arr[:size]
    non_zero = int(np.count_nonzero(np.abs(contrib_arr) > _EPS))
    indices = np.argsort(np.abs(contrib_arr))[::-1]

    items: List[Dict[str, Any]] = []
    for idx in indices:
        contribution = float(contrib_arr[idx])
        if abs(contribution) <= _EPS and items:
            break
        items.append(
            _build_feature_item(
                feature_index=int(idx),
                feature_name=feature_names[idx],
                feature_value=float(value_arr[idx]),
                contribution=contribution,
            )
        )
        if len(items) >= max(1, int(top_n)):
            break

    return {
        "non_zero_contributions": non_zero,
        "top_features": items,
    }


def random_forest_local_contributions(
    model: Any,
    feature_values: Sequence[float],
) -> Tuple[float, np.ndarray]:
    values = np.asarray(feature_values, dtype=np.float64).reshape(-1)
    if not hasattr(model, "estimators_"):
        raise RuntimeError("RandomForest estimator does not expose estimators_.")
    if not hasattr(model, "classes_"):
        raise RuntimeError("RandomForest estimator does not expose classes_.")

    classes = np.asarray(getattr(model, "classes_"))
    pos_candidates = np.where(classes == 1)[0]
    pos_index = int(pos_candidates[0]) if pos_candidates.size > 0 else min(1, len(classes) - 1)

    estimators = list(getattr(model, "estimators_", []))
    if not estimators:
        raise RuntimeError("RandomForest estimator list is empty.")

    contribution_sum = np.zeros_like(values, dtype=np.float64)
    bias_sum = 0.0

    def node_positive_probability(tree: Any, node_id: int) -> float:
        raw = np.asarray(tree.value[node_id][0], dtype=np.float64)
        denom = float(raw.sum())
        if denom <= _EPS:
            return 0.0
        if pos_index >= raw.shape[0]:
            return 0.0
        return float(raw[pos_index] / denom)

    for estimator in estimators:
        tree = estimator.tree_
        node_id = 0
        bias_sum += node_positive_probability(tree, node_id)

        while tree.children_left[node_id] != tree.children_right[node_id]:
            split_feature = int(tree.feature[node_id])
            if split_feature < 0 or split_feature >= values.size:
                break

            threshold = float(tree.threshold[node_id])
            next_node = (
                int(tree.children_left[node_id])
                if values[split_feature] <= threshold
                else int(tree.children_right[node_id])
            )

            parent_prob = node_positive_probability(tree, node_id)
            child_prob = node_positive_probability(tree, next_node)
            contribution_sum[split_feature] += child_prob - parent_prob
            node_id = next_node

    estimator_count = max(1, len(estimators))
    return float(bias_sum / estimator_count), contribution_sum / estimator_count


def build_unavailable_explainability(
    *,
    note: str,
    local_method: Optional[str] = None,
    global_method: Optional[str] = None,
    feature_space_note: Optional[str] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "available": False,
        "supports_local": False,
        "supports_global": False,
        "note": str(note),
    }
    if local_method:
        payload["local_method"] = str(local_method)
    if global_method:
        payload["global_method"] = str(global_method)
    if feature_space_note:
        payload["feature_space_note"] = str(feature_space_note)
    return payload


__all__ = [
    "GLOBAL_EXPLAIN_TOP_N",
    "LOCAL_EXPLAIN_TOP_N",
    "build_feature_names",
    "build_feature_space_note",
    "build_unavailable_explainability",
    "random_forest_local_contributions",
    "summarize_global_importance",
    "summarize_local_contributions",
]
