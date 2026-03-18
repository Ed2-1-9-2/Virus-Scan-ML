"""Helpers for consistent model metadata payloads."""

from __future__ import annotations

from typing import Any, Dict, Optional


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_ready(item) for item in value]
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            return value
    return value


def build_hyperparameter_selection(
    *,
    selection_method: str,
    validation_scheme: str,
    objective_metric: str = "roc_auc",
    selected_params: Optional[Dict[str, Any]] = None,
    search_space: Optional[Dict[str, Any]] = None,
    search_performed: bool = False,
    selected_config_name: Optional[str] = None,
    selection_notes: Optional[str] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "selection_method": str(selection_method),
        "validation_scheme": str(validation_scheme),
        "objective_metric": str(objective_metric),
        "search_performed": bool(search_performed),
        "selected_params": _json_ready(selected_params or {}),
    }
    if search_space:
        payload["search_space"] = _json_ready(search_space)
    if selected_config_name:
        payload["selected_config_name"] = str(selected_config_name)
    if selection_notes:
        payload["selection_notes"] = str(selection_notes)
    return payload


def resolve_hyperparameter_selection(model_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(model_meta, dict):
        return None

    raw = model_meta.get("hyperparameter_selection")
    if not isinstance(raw, dict):
        return None

    return build_hyperparameter_selection(
        selection_method=str(raw.get("selection_method") or "unspecified"),
        validation_scheme=str(raw.get("validation_scheme") or "unspecified"),
        objective_metric=str(raw.get("objective_metric") or "roc_auc"),
        selected_params=raw.get("selected_params") if isinstance(raw.get("selected_params"), dict) else {},
        search_space=raw.get("search_space") if isinstance(raw.get("search_space"), dict) else None,
        search_performed=bool(raw.get("search_performed")),
        selected_config_name=(
            str(raw.get("selected_config_name"))
            if raw.get("selected_config_name") not in (None, "")
            else None
        ),
        selection_notes=(
            str(raw.get("selection_notes"))
            if raw.get("selection_notes") not in (None, "")
            else None
        ),
    )


__all__ = ["build_hyperparameter_selection", "resolve_hyperparameter_selection"]
