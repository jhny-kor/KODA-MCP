from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pydantic import ValidationError

import koda_mcp.scan_service as scan_service
from koda_core import models
from koda_mcp.contracts import ChangedFile, ChangedFilesRequest, GuidanceRequest


def _raise_checker(_path, _target):
    raise RuntimeError("sentinel-checker-failure")


def _run_failing_worker(root: str, result_path: str) -> None:
    scan_service.CHECKS = (("code", _raise_checker),)
    scan_service._scan_worker(root, result_path)


def _run_cleanup_failure_probe() -> int:
    scan_service.TEMP_ROOT_BASE = Path(os.environ["KODA_TEST_TEMP_ROOT"])
    scan_service._cleanup_temp_root = lambda _root: False
    request = ChangedFilesRequest(files=[ChangedFile(path="src/a.py", content="")])
    asyncio.run(scan_service.scan_changed_files(request))
    return 99


class ScanServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.previous_root = scan_service.TEMP_ROOT_BASE
        scan_service.TEMP_ROOT_BASE = Path(self.tempdir.name) / "koda-mcp"

    def tearDown(self) -> None:
        scan_service.TEMP_ROOT_BASE = self.previous_root
        self.tempdir.cleanup()

    def _scan(self, *files: tuple[str, str]):
        request = ChangedFilesRequest(files=[ChangedFile(path=path, content=content) for path, content in files])
        return asyncio.run(scan_service.scan_changed_files(request))

    def test_completed_scan_is_redacted_and_cleaned(self) -> None:
        secret = "super-secret-sentinel-123"
        result = self._scan(
            ("src/auth.py", f'password = "{secret}"\n'),
            ("src/task.py", 'subprocess.run(request.query["cmd"], shell=True)\n'),
        )
        self.assertEqual(result.execution_status, "completed")
        self.assertEqual(result.coverage_status, "partial")
        self.assertEqual(result.selected_standard, "sw-dev-security-49")
        self.assertEqual(result.temporary_source_state, "deleted")
        self.assertGreaterEqual(len(result.findings), 1)
        self.assertTrue(all(set(item.model_dump()) == {
            "rule_id", "severity", "verification_status", "title", "path", "line", "recommendation",
            "criteria", "criteria_truncated"
        } for item in result.findings))
        secret_finding = next(item for item in result.findings if item.rule_id == "secret.generic-assignment")
        sw49 = next(item for item in secret_finding.criteria if item.standard_id == "sw-dev-security-49")
        self.assertEqual((sw49.criterion_id, sw49.criterion_labels.ko), ("S-06", "하드코드된 중요정보"))
        self.assertEqual(sw49.cwe_ids, ["CWE-259", "CWE-321", "CWE-798"])
        self.assertEqual(sw49.mapping_kind, "direct_control")
        self.assertIn("sw-dev-security-49", {item.standard_id for item in result.standard_references})
        rendered = result.model_dump_json()
        self.assertNotIn(secret, rendered)
        self.assertFalse(any(scan_service.TEMP_ROOT_BASE.glob("*")))

    def test_request_directory_name_matches_response_request_id(self) -> None:
        cleaned_roots: list[str] = []
        original_cleanup = scan_service._cleanup_temp_root

        def capture_cleanup(root: Path | None) -> bool:
            if root is not None:
                cleaned_roots.append(root.name)
            return original_cleanup(root)

        with mock.patch.object(scan_service, "_cleanup_temp_root", side_effect=capture_cleanup):
            result = self._scan(("src/a.py", ""))
        self.assertEqual(cleaned_roots, [result.request_id])

    def test_checker_exception_has_nonzero_exit_without_traceback(self) -> None:
        root = Path(self.tempdir.name) / "worker"
        root.mkdir()
        (root / "a.py").write_text("x", encoding="utf-8")
        result_path = root / ".result.json"
        process = scan_service.multiprocessing.get_context("spawn").Process(
            target=_run_failing_worker,
            args=(str(root), str(result_path)),
        )
        process.start()
        process.join(10)
        self.assertFalse(process.is_alive())
        self.assertNotEqual(process.exitcode, 0)
        self.assertEqual(
            json.loads(result_path.read_text(encoding="utf-8")),
            {"version": 1, "status": "error", "error_code": "scanner_error"},
        )

    def test_cleanup_failure_terminates_server_process(self) -> None:
        probe_root = Path(self.tempdir.name) / "cleanup-probe"
        environment = os.environ.copy()
        environment["KODA_TEST_TEMP_ROOT"] = str(probe_root)
        environment["KODA_TEST_CLEANUP_FAILURE"] = "1"
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve())],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("sentinel", result.stderr)

    def test_rejects_path_duplicates_and_file_types(self) -> None:
        cases = (
            ("/absolute.py", "invalid_path"),
            ("../parent.py", "invalid_path"),
            ("C:/drive.py", "invalid_path"),
            ("src/a.py", "duplicate_path"),
            ("archive.zip", "unsupported_file_type"),
            ("", "invalid_path"),
        )
        for path, expected in cases:
            files = ((path, "x"), ("src\\a.py", "y")) if expected == "duplicate_path" else ((path, "x"),)
            result = self._scan(*files)
            self.assertEqual(result.execution_status, "rejected", path)
            self.assertEqual(result.error_code, expected, path)
            self.assertEqual(result.temporary_source_state, "not_created")

    def test_rejects_count_and_size_limits(self) -> None:
        result = self._scan(*[(f"{index}.py", "") for index in range(21)])
        self.assertEqual(result.error_code, "too_many_files")
        result = self._scan(("large.py", "x" * (scan_service.MAX_FILE_BYTES + 1)))
        self.assertEqual(result.error_code, "file_too_large")
        result = self._scan(*[(f"{index}.py", "x" * (500 * 1024)) for index in range(11)])
        self.assertEqual(result.error_code, "request_too_large")

    def test_rejects_unicode_controls_and_every_forbidden_extension(self) -> None:
        for path in ("src/zero\x00width.py", "src/zero\u200bwidth.py", "src/control\x1fname.py"):
            result = self._scan((path, ""))
            self.assertEqual(result.error_code, "invalid_path", repr(path))
        for extension in scan_service._FORBIDDEN_EXTENSIONS:
            result = self._scan((f"artifact{extension.upper()}", ""))
            self.assertEqual(result.error_code, "unsupported_file_type", extension)

    def test_package_lockfile_gap_is_explicit_and_missing_lock_finding_is_removed(self) -> None:
        result = self._scan(("package.json", '{"dependencies":{"demo":"1.0.0"}}'))
        self.assertEqual(result.execution_status, "completed")
        self.assertIn("dependency_lockfile_presence_not_evaluated", result.coverage_gaps)
        self.assertNotIn("dependency.node-missing-lockfile", {item.rule_id for item in result.findings})

    def test_busy_does_not_create_temp_files(self) -> None:
        request = ChangedFilesRequest(files=[ChangedFile(path="src/a.py", content="")])
        with scan_service.SCAN_LOCK:
            result = asyncio.run(scan_service.scan_changed_files(request))
            guidance = scan_service.get_security_guidance(GuidanceRequest(task_summary="SQL query"))
        self.assertEqual(result.execution_status, "busy")
        self.assertEqual(result.error_code, "busy")
        self.assertFalse(scan_service.TEMP_ROOT_BASE.exists())
        self.assertTrue(guidance.items)

    def test_guidance_returns_direct_and_related_standard_criteria(self) -> None:
        guidance = scan_service.get_security_guidance(GuidanceRequest(task_summary="SQL query", language="ko"))
        item = next(item for item in guidance.items if item.rule_id == "code.sql-dynamic-query")
        direct = next(criterion for criterion in item.criteria if criterion.mapping_kind == "direct_control")
        self.assertEqual((direct.standard_id, direct.criterion_id, direct.guide_id), ("sw-dev-security-49", "I-01", "1.1"))
        self.assertEqual(direct.criterion_labels.ko, "SQL 삽입")
        self.assertEqual(
            [criterion.standard_id for criterion in item.criteria],
            ["sw-dev-security-49", "cwe-top-25-2025", "owasp-top-10-2025", "owasp-asvs-5", "owasp-proactive-controls"],
        )
        self.assertTrue(item.criteria_truncated)
        self.assertEqual(guidance.mapping_notice, "rule_mapping_not_formal_compliance")

    def test_standard_defaults_to_sw49_and_explicit_standard_filters_findings(self) -> None:
        def run_worker(standard: str) -> list[dict[str, object]]:
            root = Path(self.tempdir.name) / standard
            root.mkdir()
            source = root / "a.py"
            source.write_text("x", encoding="utf-8")
            result_path = root / ".result.json"

            def checker(path, _target):
                return [
                    models.Finding(
                        rule_id=rule_id,
                        category="code",
                        severity="high",
                        title=rule_id,
                        path=path,
                        line=1,
                        evidence="redacted",
                        description="redacted",
                        recommendation="fix",
                    )
                    for rule_id in ("code.sql-dynamic-query", "code.api-mass-assignment")
                ]

            with mock.patch.object(scan_service, "CHECKS", (("code", checker),)):
                scan_service._scan_worker(str(root), str(result_path), standard)
            return json.loads(result_path.read_text(encoding="utf-8"))["findings"]

        self.assertEqual(GuidanceRequest(task_summary="SQL").standard, "sw-dev-security-49")
        self.assertEqual(
            {item["rule_id"] for item in run_worker("sw-dev-security-49")},
            {"code.sql-dynamic-query"},
        )
        cwe_findings = run_worker("cwe-top-25-2025")
        self.assertEqual(
            {item["rule_id"] for item in cwe_findings},
            {"code.sql-dynamic-query", "code.api-mass-assignment"},
        )
        self.assertTrue(all(item["criteria"][0]["standard_id"] == "cwe-top-25-2025" for item in cwe_findings))

        with self.assertRaises(ValidationError):
            GuidanceRequest(task_summary="SQL", standard="local")

    def test_standard_criteria_stay_within_worker_result_limit(self) -> None:
        worst = 0
        for rule_id in scan_service.RULE_STANDARD_MAPPINGS:
            criteria, truncated = scan_service._criteria_for_rule(rule_id)
            item = {
                "rule_id": rule_id,
                "severity": "critical",
                "verification_status": "needs_review",
                "title": "x" * 200,
                "path": "x" * 1024,
                "line": 1,
                "recommendation": "x" * 1000,
                "criteria": criteria,
                "criteria_truncated": truncated,
            }
            payload = {"version": 1, "status": "ok", "findings": [item] * 200, "findings_truncated": True}
            worst = max(worst, len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()))
        self.assertLessEqual(worst, scan_service.MAX_RESULT_BYTES)

    def test_corrupt_worker_result_is_rejected_and_cleaned(self) -> None:
        class CorruptProcess:
            exitcode = 0

            def __init__(self, *, target, args):
                self.result_path = Path(args[1])

            def start(self) -> None:
                self.result_path.write_text("{", encoding="utf-8")

            def join(self, _timeout=None) -> None:
                return None

            def is_alive(self) -> bool:
                return False

        class CorruptContext:
            Process = CorruptProcess

        with mock.patch.object(scan_service.multiprocessing, "get_context", return_value=CorruptContext()):
            result = self._scan(("src/a.py", ""))
        self.assertEqual(result.error_code, "result_invalid")
        self.assertEqual(result.temporary_source_state, "deleted")
        self.assertFalse(any(scan_service.TEMP_ROOT_BASE.glob("*")))

    def test_timeout_terminates_child_and_cleans_temp(self) -> None:
        calls: list[object] = []

        class TimeoutProcess:
            exitcode = None

            def __init__(self, *, target, args):
                self.alive = True

            def start(self) -> None:
                calls.append("start")

            def join(self, timeout=None) -> None:
                calls.append(("join", timeout))

            def is_alive(self) -> bool:
                return self.alive

            def terminate(self) -> None:
                calls.append("terminate")

            def kill(self) -> None:
                calls.append("kill")
                self.alive = False
                self.exitcode = -9

        class TimeoutContext:
            Process = TimeoutProcess

        with mock.patch.object(scan_service.multiprocessing, "get_context", return_value=TimeoutContext()):
            result = self._scan(("src/a.py", ""))
        self.assertEqual(result.execution_status, "timed_out")
        self.assertEqual(result.temporary_source_state, "deleted")
        self.assertEqual(calls, ["start", ("join", 60.0), "terminate", ("join", 2.0), "kill", ("join", None)])
        self.assertFalse(any(scan_service.TEMP_ROOT_BASE.glob("*")))

    def test_worker_sanitizes_sorts_and_truncates_findings(self) -> None:
        root = Path(self.tempdir.name) / "bulk"
        root.mkdir()
        source_path = root / "a.py"
        source_path.write_text("sentinel-source-line", encoding="utf-8")
        result_path = root / ".result.json"

        def bulk_checker(path, _target):
            return [
                models.Finding(
                    rule_id="code.sql-dynamic-query",
                    category="code",
                    severity=("low", "critical", "high")[index % 3],
                    title="title\x00\u200b",
                    path=path,
                    line=index + 1,
                    evidence="sentinel-source-line",
                    description="sentinel-description",
                    recommendation="fix\x00this",
                )
                for index in range(205)
            ]

        with mock.patch.object(scan_service, "CHECKS", (("code", bulk_checker),)):
            scan_service._scan_worker(str(root), str(result_path))
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        rendered = json.dumps(payload)
        self.assertEqual(len(payload["findings"]), 200)
        self.assertTrue(payload["findings_truncated"])
        self.assertNotIn("sentinel", rendered)
        self.assertNotIn("evidence", rendered)
        self.assertNotIn("description", rendered)
        self.assertEqual(
            payload["findings"],
            sorted(payload["findings"], key=scan_service._finding_sort_key),
        )
        self.assertTrue(all(set(item) == {
            "rule_id", "severity", "verification_status", "title", "path", "line", "recommendation",
            "criteria", "criteria_truncated"
        } for item in payload["findings"]))
        self.assertTrue(all(item["criteria"][0]["criterion_id"] == "I-01" for item in payload["findings"]))

    def test_content_nul_is_input_validation_error(self) -> None:
        with self.assertRaises(ValidationError):
            ChangedFile(path="src/a.py", content="bad\x00content")


if __name__ == "__main__":
    if os.environ.get("KODA_TEST_CLEANUP_FAILURE") == "1":
        raise SystemExit(_run_cleanup_failure_probe())
    unittest.main()
