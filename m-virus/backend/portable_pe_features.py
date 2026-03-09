"""Portable PE feature extraction fallback for EMBER-style inference.

This module intentionally implements only the subset of raw features that the
runtime models actually consume through `flatten_ember_features()`:

- histogram (256)
- byteentropy (256)
- strings (104)
- general (10)

That matches the 626-feature legacy flattening path used by this project.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Sequence

import numpy as np

PRINTABLE_RE = re.compile(rb"[\x20-\x7f]{5,}")
PATH_RE = re.compile(rb"c:\\\\", re.IGNORECASE)
URL_RE = re.compile(rb"https?://", re.IGNORECASE)
REGISTRY_RE = re.compile(rb"hkey_", re.IGNORECASE)
MZ_RE = re.compile(rb"MZ")
PE_SIGNATURE = b"PE\x00\x00"


@dataclass(frozen=True)
class DataDirectory:
    virtual_address: int
    size: int


@dataclass(frozen=True)
class SectionHeader:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True)
class ParsedPE:
    is_pe_plus: bool
    size_of_image: int
    number_of_symbols: int
    data_directories: Sequence[DataDirectory]
    sections: Sequence[SectionHeader]


def _read_u16(bytez: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(bytez):
        raise ValueError(f"Offset out of bounds for uint16: {offset}")
    return int.from_bytes(bytez[offset : offset + 2], "little", signed=False)


def _read_u32(bytez: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(bytez):
        raise ValueError(f"Offset out of bounds for uint32: {offset}")
    return int.from_bytes(bytez[offset : offset + 4], "little", signed=False)


def _read_u64(bytez: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(bytez):
        raise ValueError(f"Offset out of bounds for uint64: {offset}")
    return int.from_bytes(bytez[offset : offset + 8], "little", signed=False)


def _parse_pe(bytez: bytes) -> ParsedPE:
    if len(bytez) < 0x40 or bytez[:2] != b"MZ":
        raise ValueError("Missing DOS header")

    pe_offset = _read_u32(bytez, 0x3C)
    if pe_offset <= 0 or pe_offset + 24 > len(bytez):
        raise ValueError("Invalid PE header offset")
    if bytez[pe_offset : pe_offset + 4] != PE_SIGNATURE:
        raise ValueError("Missing PE signature")

    coff_offset = pe_offset + 4
    number_of_sections = _read_u16(bytez, coff_offset + 2)
    number_of_symbols = _read_u32(bytez, coff_offset + 12)
    size_of_optional_header = _read_u16(bytez, coff_offset + 16)

    optional_offset = coff_offset + 20
    if optional_offset + size_of_optional_header > len(bytez):
        raise ValueError("Optional header exceeds file size")

    magic = _read_u16(bytez, optional_offset)
    if magic == 0x10B:
        is_pe_plus = False
        number_of_rva_offset = optional_offset + 92
        data_dir_offset = optional_offset + 96
    elif magic == 0x20B:
        is_pe_plus = True
        number_of_rva_offset = optional_offset + 108
        data_dir_offset = optional_offset + 112
    else:
        raise ValueError(f"Unsupported optional header magic: {hex(magic)}")

    size_of_image = _read_u32(bytez, optional_offset + 56)
    number_of_rva_and_sizes = _read_u32(bytez, number_of_rva_offset)

    data_directories: List[DataDirectory] = []
    for idx in range(min(number_of_rva_and_sizes, 16)):
        base = data_dir_offset + idx * 8
        if base + 8 > optional_offset + size_of_optional_header:
            break
        data_directories.append(
            DataDirectory(
                virtual_address=_read_u32(bytez, base),
                size=_read_u32(bytez, base + 4),
            )
        )
    while len(data_directories) < 16:
        data_directories.append(DataDirectory(virtual_address=0, size=0))

    section_offset = optional_offset + size_of_optional_header
    sections: List[SectionHeader] = []
    for idx in range(number_of_sections):
        base = section_offset + idx * 40
        if base + 40 > len(bytez):
            break
        sections.append(
            SectionHeader(
                virtual_address=_read_u32(bytez, base + 12),
                virtual_size=_read_u32(bytez, base + 8),
                raw_size=_read_u32(bytez, base + 16),
                raw_offset=_read_u32(bytez, base + 20),
            )
        )

    return ParsedPE(
        is_pe_plus=is_pe_plus,
        size_of_image=size_of_image,
        number_of_symbols=number_of_symbols,
        data_directories=data_directories,
        sections=sections,
    )


def _rva_to_offset(rva: int, sections: Sequence[SectionHeader], file_size: int) -> int | None:
    if rva <= 0:
        return None

    for section in sections:
        start = int(section.virtual_address)
        span = max(int(section.virtual_size), int(section.raw_size), 1)
        end = start + span
        if start <= rva < end:
            delta = rva - start
            if delta >= int(section.raw_size):
                return None
            offset = int(section.raw_offset) + delta
            return offset if 0 <= offset < file_size else None

    if rva < file_size:
        return rva
    return None


def _shannon_entropy(counts: np.ndarray) -> float:
    total = float(counts.sum())
    if total <= 0:
        return 0.0
    probs = counts[counts > 0].astype(np.float64) / total
    return float(-(probs * np.log2(probs)).sum())


def _byte_histogram(bytez: bytes) -> List[int]:
    if not bytez:
        return [0] * 256
    data = np.frombuffer(bytez, dtype=np.uint8)
    return np.bincount(data, minlength=256).astype(np.int64).tolist()


def _byte_entropy_histogram(bytez: bytes, window: int = 2048, step: int = 1024) -> List[int]:
    if not bytez:
        return [0] * 256

    data = np.frombuffer(bytez, dtype=np.uint8)
    output = np.zeros((16, 16), dtype=np.int64)

    if data.size <= window:
        starts = [0]
    else:
        starts = range(0, data.size - window + 1, step)

    for start in starts:
        block = data[start : start + window]
        coarse_counts = np.bincount(block >> 4, minlength=16)
        entropy = min(7.999999, _shannon_entropy(coarse_counts) * 2.0)
        entropy_bin = min(15, int(entropy * 2.0))
        output[entropy_bin] += coarse_counts

    return output.reshape(-1).tolist()


def _string_features(bytez: bytes) -> Dict[str, object]:
    strings = PRINTABLE_RE.findall(bytez)
    num_strings = len(strings)
    avg_length = float(sum(len(item) for item in strings) / num_strings) if num_strings else 0.0

    if strings:
        joined = b"".join(strings)
        values = np.frombuffer(joined, dtype=np.uint8) - 0x20
        printable_dist = np.bincount(values, minlength=96).astype(np.int64)
    else:
        printable_dist = np.zeros(96, dtype=np.int64)

    printable_total = int(printable_dist.sum())

    return {
        "numstrings": int(num_strings),
        "avlength": avg_length,
        "printabledist": printable_dist.tolist(),
        "printables": printable_total,
        "entropy": _shannon_entropy(printable_dist),
        "paths": len(PATH_RE.findall(bytez)),
        "urls": len(URL_RE.findall(bytez)),
        "registry": len(REGISTRY_RE.findall(bytez)),
        "MZ": len(MZ_RE.findall(bytez)),
    }


def _count_imported_functions(bytez: bytes, pe: ParsedPE) -> int:
    directory = pe.data_directories[1]
    table_offset = _rva_to_offset(directory.virtual_address, pe.sections, len(bytez))
    if table_offset is None:
        return 0

    thunk_size = 8 if pe.is_pe_plus else 4
    total = 0
    for idx in range(4096):
        base = table_offset + idx * 20
        if base + 20 > len(bytez):
            break
        original_first_thunk = _read_u32(bytez, base)
        time_date_stamp = _read_u32(bytez, base + 4)
        forwarder_chain = _read_u32(bytez, base + 8)
        name_rva = _read_u32(bytez, base + 12)
        first_thunk = _read_u32(bytez, base + 16)
        if (
            original_first_thunk == 0
            and time_date_stamp == 0
            and forwarder_chain == 0
            and name_rva == 0
            and first_thunk == 0
        ):
            break

        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = _rva_to_offset(thunk_rva, pe.sections, len(bytez))
        if thunk_offset is None:
            continue

        for thunk_idx in range(65536):
            entry_offset = thunk_offset + thunk_idx * thunk_size
            if entry_offset + thunk_size > len(bytez):
                break
            value = (
                _read_u64(bytez, entry_offset)
                if pe.is_pe_plus
                else _read_u32(bytez, entry_offset)
            )
            if value == 0:
                break
            total += 1
    return total


def _count_exported_functions(bytez: bytes, pe: ParsedPE) -> int:
    directory = pe.data_directories[0]
    table_offset = _rva_to_offset(directory.virtual_address, pe.sections, len(bytez))
    if table_offset is None or table_offset + 40 > len(bytez):
        return 0

    number_of_functions = _read_u32(bytez, table_offset + 20)
    number_of_names = _read_u32(bytez, table_offset + 24)
    return int(max(number_of_functions, number_of_names))


def _general_features(bytez: bytes, pe: ParsedPE) -> Dict[str, int]:
    directories = pe.data_directories
    return {
        "size": int(len(bytez)),
        "vsize": int(pe.size_of_image or len(bytez)),
        "has_debug": int(directories[6].virtual_address > 0 and directories[6].size > 0),
        "exports": int(_count_exported_functions(bytez, pe)),
        "imports": int(_count_imported_functions(bytez, pe)),
        "has_relocations": int(directories[5].virtual_address > 0 and directories[5].size > 0),
        "has_resources": int(directories[2].virtual_address > 0 and directories[2].size > 0),
        "has_signature": int(directories[4].size > 0),
        "has_tls": int(directories[9].virtual_address > 0 and directories[9].size > 0),
        "symbols": int(pe.number_of_symbols),
    }


class PortablePEFeatureExtractor:
    """Minimal runtime-compatible fallback for EMBER's PEFeatureExtractor."""

    def __init__(self, feature_version: int = 2, **_: object) -> None:
        self.feature_version = int(feature_version)

    def raw_features(self, bytez: bytes) -> Dict[str, object]:
        try:
            pe = _parse_pe(bytez)
        except Exception as exc:
            raise RuntimeError(f"Invalid PE file: {exc}") from exc

        return {
            "histogram": _byte_histogram(bytez),
            "byteentropy": _byte_entropy_histogram(bytez),
            "strings": _string_features(bytez),
            "general": _general_features(bytez, pe),
            "header": {},
            "section": {},
            "imports": {},
            "exports": [],
        }


__all__ = ["PortablePEFeatureExtractor"]
