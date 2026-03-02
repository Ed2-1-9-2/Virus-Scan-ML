"""CLI helper: upload local PE file to API /predict-file endpoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import requests


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Upload a PE file to API /predict-file and print prediction"
    )
    parser.add_argument("--file", required=True, help="Path to PE file (.exe/.dll/.sys/etc)")
    parser.add_argument("--api-url", default="http://localhost:8000", help="API base URL")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    target = Path(args.file)

    if not target.exists():
        raise FileNotFoundError(f"File not found: {target}")

    with target.open("rb") as handle:
        files = {"file": (target.name, handle, "application/octet-stream")}
        response = requests.post(f"{args.api_url.rstrip('/')}/predict-file", files=files, timeout=120)

    if response.status_code >= 400:
        try:
            print(json.dumps(response.json(), indent=2))
        except Exception:
            print(response.text)
        response.raise_for_status()

    print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
