"""Batch malware detection utilities for EMBER-style JSONL files."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.model_core import XGBoostMalwareModel, iter_jsonl_records


class BatchMalwareDetector:
    def __init__(
        self,
        model_path: str | Path = PROJECT_ROOT / "models" / "xgboost_malware_model.json",
        metadata_path: str | Path = PROJECT_ROOT / "models" / "model_metadata.json",
        threshold: Optional[float] = None,
    ) -> None:
        self.runtime = XGBoostMalwareModel(
            model_path=model_path,
            metadata_path=metadata_path,
            threshold=threshold,
        )
        self.results: List[tuple[str, pd.DataFrame]] = []

    def process_jsonl_file(
        self,
        filepath: str | Path,
        output_csv: Optional[str | Path] = None,
        progress_every: int = 1000,
        limit: Optional[int] = None,
    ) -> pd.DataFrame:
        target = Path(filepath)
        if not target.exists():
            raise FileNotFoundError(f"File not found: {target}")

        print(f"\nProcessing: {target}")

        rows: List[Dict] = []
        malware_count = 0
        benign_count = 0

        for idx, record in enumerate(iter_jsonl_records(target), start=1):
            if limit is not None and idx > limit:
                break

            result = self.runtime.predict_ember_record(record)
            prediction = result["prediction"]

            if prediction == "Malware":
                malware_count += 1
            else:
                benign_count += 1

            rows.append(
                {
                    "sha256": result.get("sha256") or record.get("sha256") or f"unknown_{idx}",
                    "prediction": prediction,
                    "probability_malware": result["probability_malware"],
                    "confidence": result["confidence"],
                    "file_index": idx - 1,
                }
            )

            if progress_every > 0 and idx % progress_every == 0:
                print(
                    f"  Processed {idx} files "
                    f"({malware_count} malware, {benign_count} benign)"
                )

        df = pd.DataFrame(rows)

        if not df.empty:
            avg_conf = float(df["confidence"].mean())
            malware_pct = 100.0 * malware_count / len(df)
            benign_pct = 100.0 * benign_count / len(df)
        else:
            avg_conf = 0.0
            malware_pct = 0.0
            benign_pct = 0.0

        print("\n" + "=" * 70)
        print(f"PROCESSING COMPLETE: {target.name}")
        print("=" * 70)
        print(f"Total files: {len(df)}")
        print(f"Malware detected: {malware_count} ({malware_pct:.2f}%)")
        print(f"Benign files: {benign_count} ({benign_pct:.2f}%)")
        print(f"Average confidence: {avg_conf:.4f}")

        if output_csv:
            out_path = Path(output_csv)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            df.to_csv(out_path, index=False)
            print(f"Results saved to: {out_path}")

        self.results.append((target.name, df))
        return df

    def process_directory(
        self,
        directory: str | Path,
        pattern: str = "*.jsonl",
        output_dir: Optional[str | Path] = None,
        limit_per_file: Optional[int] = None,
    ) -> Dict[str, pd.DataFrame]:
        directory = Path(directory)
        files = sorted(directory.glob(pattern))
        print(f"Found {len(files)} files matching '{pattern}' in {directory}")

        all_results: Dict[str, pd.DataFrame] = {}
        for filepath in files:
            out_csv = None
            if output_dir:
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                out_csv = output_path / f"{filepath.stem}_predictions.csv"

            all_results[filepath.name] = self.process_jsonl_file(
                filepath,
                output_csv=out_csv,
                limit=limit_per_file,
            )

        return all_results

    def generate_summary_report(
        self, output_file: str | Path = PROJECT_ROOT / "reports" / "malware_detection_summary.txt"
    ) -> Path:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        total_malware = 0
        total_benign = 0
        total_files = 0

        with output_path.open("w", encoding="utf-8") as handle:
            handle.write("=" * 70 + "\n")
            handle.write("MALWARE DETECTION SUMMARY REPORT\n")
            handle.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            handle.write("=" * 70 + "\n\n")

            for filename, df in self.results:
                malware = int((df["prediction"] == "Malware").sum()) if not df.empty else 0
                benign = int((df["prediction"] == "Benign").sum()) if not df.empty else 0
                total = len(df)

                total_malware += malware
                total_benign += benign
                total_files += total

                avg_conf = float(df["confidence"].mean()) if not df.empty else 0.0
                high_risk = int((df["probability_malware"] > 0.9).sum()) if not df.empty else 0

                handle.write(f"File: {filename}\n")
                handle.write(f"  Total: {total}\n")
                handle.write(f"  Malware: {malware} ({(100.0 * malware / total) if total else 0.0:.2f}%)\n")
                handle.write(f"  Benign: {benign} ({(100.0 * benign / total) if total else 0.0:.2f}%)\n")
                handle.write(f"  Avg Confidence: {avg_conf:.4f}\n")
                handle.write(f"  High Risk (>0.9): {high_risk}\n\n")

            handle.write("=" * 70 + "\n")
            handle.write("OVERALL SUMMARY\n")
            handle.write("=" * 70 + "\n")
            handle.write(f"Total Files Scanned: {total_files}\n")
            handle.write(
                f"Total Malware: {total_malware} "
                f"({(100.0 * total_malware / total_files) if total_files else 0.0:.2f}%)\n"
            )
            handle.write(
                f"Total Benign: {total_benign} "
                f"({(100.0 * total_benign / total_files) if total_files else 0.0:.2f}%)\n"
            )

        print(f"\nReport saved to: {output_path}")
        return output_path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Batch malware scanning for EMBER JSONL files.")
    parser.add_argument(
        "--model",
        default=str(PROJECT_ROOT / "models" / "xgboost_malware_model.json"),
        help="Path to model file.",
    )
    parser.add_argument(
        "--metadata",
        default=str(PROJECT_ROOT / "models" / "model_metadata.json"),
        help="Optional metadata path.",
    )
    parser.add_argument(
        "--input",
        default=str(PROJECT_ROOT / "ember_dataset" / "test_features.jsonl"),
        help="Input JSONL file path.",
    )
    parser.add_argument(
        "--output-csv",
        default=None,
        help="Optional CSV output path.",
    )
    parser.add_argument(
        "--summary",
        default=str(PROJECT_ROOT / "reports" / "malware_detection_summary.txt"),
        help="Summary report output path.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional max number of records to process.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Override decision threshold.",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    detector = BatchMalwareDetector(
        model_path=args.model,
        metadata_path=args.metadata,
        threshold=args.threshold,
    )

    df = detector.process_jsonl_file(
        filepath=args.input,
        output_csv=args.output_csv,
        limit=args.limit,
    )

    if not df.empty:
        print("\nSample predictions:")
        for _, row in df.head(5).iterrows():
            sha = str(row["sha256"])[:16]
            pred = row["prediction"]
            prob = row["probability_malware"]
            print(f"  {sha}... -> {pred} (p_malware={prob:.4f})")

    detector.generate_summary_report(args.summary)


if __name__ == "__main__":
    main()
