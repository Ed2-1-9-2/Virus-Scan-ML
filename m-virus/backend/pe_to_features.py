"""Helpers to extract EMBER-like raw/static features from PE files.

This module is optional at runtime: when extraction dependencies are unavailable,
APIs/scripts should surface a clear actionable message.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from typing import Dict, Optional, Tuple

import numpy as np

from backend.model_core import flatten_ember_features, normalize_features

_PE_EXTRACTOR_CLASS = None
_IMPORT_ERROR: Optional[Exception] = None
_EXTRACTOR = None


def _patch_numpy_compat() -> None:
    """
    Restore deprecated NumPy aliases used by older EMBER/LIEF-based extractors.

    NumPy 1.24+ removed aliases like np.int/np.float/np.bool that some legacy
    malware-feature code still references.
    """
    alias_map = {
        "int": int,
        "float": float,
        "bool": bool,
        "object": object,
        "complex": complex,
        "long": int,
    }
    for alias, target in alias_map.items():
        # Use numpy.__dict__ to avoid FutureWarning emitted by hasattr on some aliases.
        if alias not in np.__dict__:
            setattr(np, alias, target)


def _patch_lief_compat(lief_module) -> None:
    """
    Patch missing LIEF exception symbols expected by old EMBER feature code.

    Newer LIEF versions removed several top-level exception classes that EMBER
    references directly when building exception tuples.
    """
    for name in ("bad_format", "bad_file", "pe_error", "parser_error", "read_out_of_bound"):
        if not hasattr(lief_module, name):
            setattr(lief_module, name, RuntimeError)


def _load_pe_extractor_class():
    """
    Load PEFeatureExtractor in a resilient way.

    1) Try normal `import ember` path.
    2) If that fails (often due optional deps in ember.__init__), load
       `ember/features.py` directly and import PEFeatureExtractor only.
    """
    global _PE_EXTRACTOR_CLASS, _IMPORT_ERROR

    if _PE_EXTRACTOR_CLASS is not None:
        return _PE_EXTRACTOR_CLASS

    _patch_numpy_compat()

    try:
        import ember  # type: ignore

        cls = getattr(ember, "PEFeatureExtractor", None)
        if cls is not None:
            try:
                import lief  # type: ignore

                _patch_lief_compat(lief)
            except Exception:
                pass
            _PE_EXTRACTOR_CLASS = cls
            return _PE_EXTRACTOR_CLASS
    except Exception as exc:  # pragma: no cover - optional dependency path
        _IMPORT_ERROR = exc

    try:
        spec = importlib.util.find_spec("ember")
        if spec and spec.submodule_search_locations:
            base = Path(list(spec.submodule_search_locations)[0])
            features_path = base / "features.py"
            if features_path.exists():
                file_spec = importlib.util.spec_from_file_location(
                    "ember_features_only", str(features_path)
                )
                if file_spec and file_spec.loader:
                    module = importlib.util.module_from_spec(file_spec)
                    file_spec.loader.exec_module(module)
                    try:
                        _patch_lief_compat(module.lief)
                    except Exception:
                        pass
                    cls = getattr(module, "PEFeatureExtractor", None)
                    if cls is not None:
                        _PE_EXTRACTOR_CLASS = cls
                        return _PE_EXTRACTOR_CLASS
    except Exception as exc:  # pragma: no cover - optional dependency path
        _IMPORT_ERROR = exc

    return None


def extractor_available() -> bool:
    return _load_pe_extractor_class() is not None


def extractor_diagnostics() -> str:
    if extractor_available():
        return "available"

    if _IMPORT_ERROR is not None:
        return f"unavailable: {_IMPORT_ERROR.__class__.__name__}: {_IMPORT_ERROR}"

    return "unavailable: PEFeatureExtractor could not be loaded"


def _get_extractor():
    global _EXTRACTOR

    cls = _load_pe_extractor_class()
    if cls is None:
        raise RuntimeError(
            "PE extraction dependencies missing. "
            "Install optional deps (config/requirements-optional.txt) and ensure `lief` is installed. "
            f"Details: {extractor_diagnostics()}"
        )

    if _EXTRACTOR is None:
        _EXTRACTOR = cls(feature_version=2)

    return _EXTRACTOR


def sha256_bytes(bytez: bytes) -> str:
    return hashlib.sha256(bytez).hexdigest()


def extract_raw_from_bytes(bytez: bytes) -> Dict:
    extractor = _get_extractor()
    raw = extractor.raw_features(bytez)
    if not isinstance(raw, dict):
        raise RuntimeError("EMBER extractor returned invalid raw feature structure")
    return raw


def extract_model_features_from_bytes(bytez: bytes, expected_length: int) -> Tuple[np.ndarray, Dict]:
    raw = extract_raw_from_bytes(bytez)
    features = flatten_ember_features(raw)
    features = normalize_features(features, expected_length)
    return features, raw


def extract_model_features_from_file(path: str | Path, expected_length: int) -> Tuple[np.ndarray, Dict, str]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    data = file_path.read_bytes()
    features, raw = extract_model_features_from_bytes(data, expected_length)
    return features, raw, sha256_bytes(data)
