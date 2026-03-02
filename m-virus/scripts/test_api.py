#!/usr/bin/env python3
"""API validation script for the reduced frontend-focused backend."""

from __future__ import annotations

import io
import json
import time
from typing import Dict, List
import zipfile

import requests


class APITester:
    def __init__(self, base_url: str = "http://localhost:8000") -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.test_results: List[Dict[str, str]] = []

    def print_section(self, title: str) -> None:
        print("\n" + "=" * 70)
        print(f"  {title}")
        print("=" * 70)

    def print_test(self, name: str, status: str, details: str = "") -> None:
        status_symbol = {"PASS": "[OK]", "FAIL": "[FAIL]", "WARN": "[WARN]"}.get(
            status, "[?]"
        )
        print(f"\n{status_symbol} {name}")
        if details:
            print(f"   {details}")

        self.test_results.append({"name": name, "status": status, "details": details})

    def test_health(self) -> bool:
        self.print_section("TEST 1: Health Check")

        try:
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            response.raise_for_status()
            data = response.json()

            print(json.dumps(data, indent=2))

            ok = data.get("status") in {"healthy", "degraded"}
            if ok:
                self.print_test(
                    "Health Check",
                    "PASS",
                    f"Status={data.get('status')} model_loaded={data.get('model_loaded')}",
                )
                return True

            self.print_test("Health Check", "FAIL", "Unexpected status payload")
            return False
        except Exception as exc:
            self.print_test("Health Check", "FAIL", f"Error: {exc}")
            return False

    def test_model_info(self) -> bool:
        self.print_section("TEST 2: Model Information")

        try:
            response = self.session.get(f"{self.base_url}/model-info", timeout=10)
            response.raise_for_status()
            data = response.json()
            print(json.dumps(data, indent=2))

            required = {"model_type", "input_features", "threshold"}
            missing = required - set(data.keys())
            if missing:
                self.print_test("Model Info", "FAIL", f"Missing fields: {sorted(missing)}")
                return False

            self.print_test(
                "Model Info",
                "PASS",
                f"Features={data.get('input_features')} threshold={data.get('threshold')}",
            )
            return True
        except Exception as exc:
            self.print_test("Model Info", "FAIL", f"Error: {exc}")
            return False

    def test_predict_file_endpoint(self) -> bool:
        self.print_section("TEST 3: Predict PE File Endpoint")

        try:
            info = self.session.get(f"{self.base_url}/model-info", timeout=10).json()
            extraction_available = bool(info.get("pe_file_extraction_available", False))

            # tiny fake PE-like payload; endpoint contract/availability test only.
            files = {"file": ("dummy.exe", b"MZFAKE", "application/octet-stream")}
            response = self.session.post(f"{self.base_url}/predict-file", files=files, timeout=20)

            if extraction_available:
                if response.status_code in {200, 400, 500}:
                    self.print_test(
                        "Predict PE File Endpoint",
                        "PASS",
                        f"Endpoint reachable; extractor enabled (status={response.status_code}).",
                    )
                    return True
                self.print_test(
                    "Predict PE File Endpoint",
                    "FAIL",
                    f"Unexpected status {response.status_code} with extractor enabled",
                )
                return False

            if response.status_code == 503:
                self.print_test(
                    "Predict PE File Endpoint",
                    "PASS",
                    "Endpoint reachable; optional extractor not installed (expected 503).",
                )
                return True

            self.print_test(
                "Predict PE File Endpoint",
                "FAIL",
                f"Unexpected status {response.status_code} when extractor disabled",
            )
            return False
        except Exception as exc:
            self.print_test("Predict PE File Endpoint", "FAIL", f"Error: {exc}")
            return False

    def test_scan_archive_endpoint(self) -> bool:
        self.print_section("TEST 4: Scan Archive Endpoint")

        try:
            info = self.session.get(f"{self.base_url}/model-info", timeout=10).json()
            extraction_available = bool(info.get("pe_file_extraction_available", False))

            archive_buffer = io.BytesIO()
            with zipfile.ZipFile(archive_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("sample.exe", b"MZFAKE")
                zf.writestr("note.txt", b"hello")

            files = {"file": ("sample.zip", archive_buffer.getvalue(), "application/zip")}
            response = self.session.post(f"{self.base_url}/scan-archive", files=files, timeout=30)

            if extraction_available:
                if response.status_code != 200:
                    self.print_test(
                        "Scan Archive Endpoint",
                        "FAIL",
                        f"Expected 200 with extractor enabled, got {response.status_code}",
                    )
                    return False

                payload = response.json()
                required = {"archive_type", "total_entries", "scanned_files", "malware_count", "benign_count"}
                missing = required - set(payload.keys())
                if missing:
                    self.print_test("Scan Archive Endpoint", "FAIL", f"Missing fields: {sorted(missing)}")
                    return False

                self.print_test(
                    "Scan Archive Endpoint",
                    "PASS",
                    f"type={payload.get('archive_type')} scanned={payload.get('scanned_files')}",
                )
                return True

            if response.status_code == 503:
                self.print_test(
                    "Scan Archive Endpoint",
                    "PASS",
                    "Endpoint reachable; optional extractor not installed (expected 503).",
                )
                return True

            self.print_test(
                "Scan Archive Endpoint",
                "FAIL",
                f"Unexpected status {response.status_code} when extractor disabled",
            )
            return False
        except Exception as exc:
            self.print_test("Scan Archive Endpoint", "FAIL", f"Error: {exc}")
            return False

    def test_irrelevant_routes_removed(self) -> bool:
        self.print_section("TEST 5: Removed Routes")

        removed = ["/predict", "/predict-batch", "/scan-jsonl", "/scan-results/test", "/stats"]
        all_ok = True
        details: List[str] = []

        for path in removed:
            resp = self.session.get(f"{self.base_url}{path}", timeout=10)
            if resp.status_code in {404, 405}:
                details.append(f"{path}={resp.status_code}")
            else:
                all_ok = False
                details.append(f"{path}={resp.status_code} (unexpected)")

        self.print_test(
            "Removed Routes",
            "PASS" if all_ok else "FAIL",
            ", ".join(details),
        )
        return all_ok

    def test_cors_and_response_times(self) -> bool:
        self.print_section("TEST 6: CORS + Response Times")

        try:
            options_response = self.session.options(
                f"{self.base_url}/predict-file",
                headers={
                    "Origin": "http://localhost:3000",
                    "Access-Control-Request-Method": "POST",
                },
                timeout=10,
            )
            origin = options_response.headers.get("Access-Control-Allow-Origin")
            if not origin:
                self.print_test("CORS", "FAIL", "No CORS headers on preflight response")
                return False

            endpoints = ["/health", "/model-info"]
            elapsed_ms: List[float] = []
            for endpoint in endpoints:
                t0 = time.time()
                response = self.session.get(f"{self.base_url}{endpoint}", timeout=10)
                response.raise_for_status()
                elapsed_ms.append((time.time() - t0) * 1000.0)

            avg = sum(elapsed_ms) / len(elapsed_ms)
            self.print_test("CORS + Response Times", "PASS", f"allow-origin={origin}, avg={avg:.2f}ms")
            return True
        except Exception as exc:
            self.print_test("CORS + Response Times", "FAIL", f"Error: {exc}")
            return False

    def generate_report(self) -> None:
        self.print_section("TEST SUMMARY")
        passed = sum(1 for t in self.test_results if t["status"] == "PASS")
        failed = sum(1 for t in self.test_results if t["status"] == "FAIL")
        warned = sum(1 for t in self.test_results if t["status"] == "WARN")
        total = len(self.test_results)

        print(f"Tests run:   {total}")
        print(f"Passed:      {passed}")
        print(f"Warnings:    {warned}")
        print(f"Failed:      {failed}")
        print(f"Success:     {(passed / total) * 100:.1f}%")

    def run_all_tests(self) -> None:
        print("\n" + "=" * 70)
        print("Reduced API Test Suite")
        print("=" * 70)

        try:
            self.session.get(f"{self.base_url}/health", timeout=5)
        except Exception:
            print(f"\n[FAIL] Cannot reach API at {self.base_url}")
            print("Start it with: .\\.venv\\Scripts\\python.exe -m backend.api_backend")
            return

        self.test_health()
        self.test_model_info()
        self.test_predict_file_endpoint()
        self.test_scan_archive_endpoint()
        self.test_irrelevant_routes_removed()
        self.test_cors_and_response_times()

        self.generate_report()
        print(f"\nDocs: {self.base_url}/docs")


if __name__ == "__main__":
    import sys

    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    APITester(target_url).run_all_tests()
