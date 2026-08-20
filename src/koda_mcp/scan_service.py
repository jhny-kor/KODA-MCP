from __future__ import annotations

import asyncio
import json
import multiprocessing
import os
import re
import shutil
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from koda_core import models
from koda_core.checks import code_patterns, common, configuration, dependencies, secrets

from .contracts import (
    ChangedFilesRequest,
    GuidanceItem,
    GuidanceRequest,
    GuidanceResponse,
    ScanEngine,
    ScanFinding,
    ScanResponse,
    StandardId,
)
from .standard_catalog_data import RULE_STANDARD_MAPPINGS, STANDARD_ORDER, STANDARD_REFERENCES


MCP_SERVER_VERSION = "0.1.0"
MCP_SDK_VERSION = "2.0.0"
KODA_SOURCE_COMMIT = "b2987c1211e745aa9dc99db94e0ad7eb73cc11e4"
KODA_SOURCE_TREE_SHA256 = "adbf09b9f24cd14e01472b4878150dd86a36bfc7261b130fd4017cd955ac5376"

MAX_FILES = 20
MAX_FILE_BYTES = 512 * 1024
MAX_REQUEST_BYTES = 5 * 1024 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_CRITERIA_PER_RULE = 5
MAX_SNIPPET_CHARS = 500
DEFAULT_STANDARD_ID: StandardId = "sw-dev-security-49"
SCAN_TIMEOUT_SECONDS = 60.0
TEMP_ROOT_BASE = Path("/tmp/koda-mcp")
_PATH_RULE = re.compile(r"^[A-Za-z]:")
_RULE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_FORBIDDEN_EXTENSIONS = frozenset(
    ".zip .tar .gz .tgz .bz2 .xz .7z .rar .jar .war .ear .whl "
    ".exe .dll .so .dylib .o .obj .a .class .pyc .pyo .bin "
    ".png .jpg .jpeg .gif .webp .ico .pdf .doc .docx .xls .xlsx "
    ".ppt .pptx .mp3 .mp4 .mov .avi .woff .woff2 .ttf .otf "
    ".db .sqlite .sqlite3"
    .split()
)
_COVERAGE_GAPS = [
    "provided_files_only",
    "project_context_not_evaluated",
    "dependency_resolution_not_evaluated",
    "runtime_not_evaluated",
    "formal_compliance_not_evaluated",
    "file_selection_agent_controlled",
]
_SEVERITY_RANK = {severity: index for index, severity in enumerate(models.SEVERITIES)}

# ponytail: global lock, per-account workers only if one-at-a-time becomes a measured bottleneck.
SCAN_LOCK = threading.Lock()
CHECKS = (
    ("secrets", secrets.check_file),
    ("dependencies", dependencies.check_file),
    ("configuration", configuration.check_file),
    ("code", code_patterns.check_file),
)
GUIDANCE_RULE_IDS = (
    "secret.generic-assignment",
    "code.auth-disabled-endpoint",
    "code.sql-dynamic-query",
    "code.command-injection",
    "code.path-traversal",
    "code.unsafe-deserialization",
    "code.ssrf-user-url",
    "code.unrestricted-file-upload",
)
_GUIDANCE_TERMS = {
    "secret.generic-assignment": ("secret", "password", "token", "key", "비밀", "암호", "자격증명"),
    "code.auth-disabled-endpoint": ("auth", "login", "session", "permission", "인증", "로그인", "세션", "권한"),
    "code.sql-dynamic-query": ("sql", "query", "database", "db", "쿼리", "데이터베이스"),
    "code.command-injection": ("command", "shell", "subprocess", "exec", "명령", "쉘"),
    "code.path-traversal": ("path", "file", "upload", "경로", "파일", "업로드"),
    "code.unsafe-deserialization": ("deserialize", "pickle", "yaml", "역직렬화"),
    "code.ssrf-user-url": ("url", "http", "request", "ssrf", "네트워크", "주소"),
    "code.unrestricted-file-upload": ("upload", "multipart", "파일 업로드"),
}
_GUIDANCE_KO = {
    "secret.generic-assignment": ("하드코딩된 비밀값 가능성", "비밀값은 환경변수나 로컬 비밀 저장소로 분리하고 실제 값이면 교체하세요."),
    "code.auth-disabled-endpoint": ("인증·인가 우회 가능성", "공개 의도가 없는 엔드포인트에는 인증과 객체별 인가를 적용하세요."),
    "code.sql-dynamic-query": ("동적 SQL 주입 가능성", "문자열 조합 대신 파라미터 바인딩 또는 안전한 ORM API를 사용하세요."),
    "code.command-injection": ("명령 주입 가능성", "셸 실행을 피하고 고정된 인자 배열과 허용 목록을 사용하세요."),
    "code.path-traversal": ("경로 순회 가능성", "허용된 기준 디렉터리 안에서 경로를 해석하고 순회 segment를 거부하세요."),
    "code.unsafe-deserialization": ("안전하지 않은 역직렬화 API", "신뢰할 수 없는 입력에는 안전한 파서를 사용하고 역직렬화를 제한하세요."),
    "code.ssrf-user-url": ("사용자 URL 기반 SSRF 가능성", "허용된 스킴·호스트·포트만 검증한 뒤 서버 요청을 수행하세요."),
    "code.unrestricted-file-upload": ("제한 없는 파일 업로드 가능성", "크기·확장자·콘텐츠·저장 위치를 제한하고 실행 경로와 분리하세요."),
}


@dataclass(frozen=True)
class _ValidatedFile:
    path: str
    content: bytes


def _engine() -> ScanEngine:
    return ScanEngine(
        mcp_server_version=MCP_SERVER_VERSION,
        mcp_sdk_version=MCP_SDK_VERSION,
        koda_source_commit=KODA_SOURCE_COMMIT,
        koda_source_tree_sha256=KODA_SOURCE_TREE_SHA256,
    )


def _criteria_for_rule(
    rule_id: str,
    selected_standard: StandardId = DEFAULT_STANDARD_ID,
) -> tuple[list[dict[str, Any]], bool]:
    mappings = RULE_STANDARD_MAPPINGS.get(rule_id, ())
    if selected_standard == "all":
        return [dict(item) for item in mappings], False
    selected = [item for item in mappings if item["standard_id"] == selected_standard][:MAX_CRITERIA_PER_RULE]
    represented = {item["standard_id"] for item in selected}
    for item in mappings:
        if len(selected) == MAX_CRITERIA_PER_RULE:
            break
        if item["standard_id"] not in represented:
            selected.append(item)
            represented.add(item["standard_id"])
    if len(selected) < MAX_CRITERIA_PER_RULE:
        selected.extend(
            [item for item in mappings if item not in selected][: MAX_CRITERIA_PER_RULE - len(selected)]
        )
    return [dict(item) for item in selected], len(mappings) > len(selected)


def _rule_matches_standard(rule_id: str, standard_id: StandardId) -> bool:
    return standard_id == "all" or any(
        item["standard_id"] == standard_id for item in RULE_STANDARD_MAPPINGS.get(rule_id, ())
    )


def _standard_references_for_rules(
    rule_ids: set[str],
    selected_standard: StandardId,
) -> list[dict[str, Any]]:
    if selected_standard == "all":
        return [STANDARD_REFERENCES[standard_id] for standard_id in STANDARD_ORDER]
    referenced = {selected_standard} | {
        item["standard_id"]
        for rule_id in rule_ids
        for item in _criteria_for_rule(rule_id, selected_standard)[0]
    }
    order = (selected_standard, *(standard_id for standard_id in STANDARD_ORDER if standard_id != selected_standard))
    return [STANDARD_REFERENCES[standard_id] for standard_id in order if standard_id in referenced]


def _response(
    request_id: str,
    file_count: int,
    selected_standard: StandardId,
    *,
    execution_status: str,
    coverage_status: str,
    temporary_source_state: str,
    error_code: str | None,
    coverage_gaps: list[str],
    findings: list[ScanFinding] | None = None,
    findings_truncated: bool = False,
) -> ScanResponse:
    return ScanResponse(
        request_id=request_id,
        execution_status=execution_status,
        coverage_status=coverage_status,
        selected_standard=selected_standard,
        received_file_count=file_count,
        findings_truncated=findings_truncated,
        temporary_source_state=temporary_source_state,
        error_code=error_code,
        coverage_gaps=coverage_gaps,
        findings=findings or [],
        standard_references=_standard_references_for_rules(
            {finding.rule_id for finding in findings or []},
            selected_standard,
        ),
        engine=_engine(),
    )


def _remove_control_characters(value: str, limit: int, default: str) -> str:
    cleaned = "".join(
        character
        for character in value
        if unicodedata.category(character) not in {"Cc", "Cf"}
    )[:limit]
    return cleaned or default


def _rule_metadata(rule_id: str) -> tuple[str, str]:
    for rule in secrets.SECRET_RULES:
        if rule.rule_id == rule_id:
            return rule.title, rule.recommendation
    rule = next((item for item in code_patterns.CODE_PATTERN_RULES if item.rule_id == rule_id), None)
    if rule is None:
        raise RuntimeError(f"guidance rule is not present in copied core: {rule_id}")
    return rule.title, rule.recommendation


def get_security_guidance(request: GuidanceRequest) -> GuidanceResponse:
    summary = request.task_summary.casefold()
    candidates = [
        rule_id for rule_id in GUIDANCE_RULE_IDS if _rule_matches_standard(rule_id, request.standard)
    ]
    selected = [
        rule_id
        for rule_id in candidates
        if any(term.casefold() in summary for term in _GUIDANCE_TERMS[rule_id])
    ]
    if not selected:
        selected = candidates

    items: list[GuidanceItem] = []
    for rule_id in selected[:8]:
        title, recommendation = _rule_metadata(rule_id)
        if request.language == "ko":
            title, recommendation = _GUIDANCE_KO[rule_id]
        criteria, criteria_truncated = _criteria_for_rule(rule_id, request.standard)
        items.append(
            GuidanceItem(
                rule_id=rule_id,
                title=title,
                recommendation=recommendation,
                criteria=criteria,
                criteria_truncated=criteria_truncated,
            )
        )
    return GuidanceResponse(
        selected_standard=request.standard,
        items=items,
        standard_references=_standard_references_for_rules(
            {item.rule_id for item in items},
            request.standard,
        ),
    )


class _InvalidFileSet(ValueError):
    def __init__(self, error_code: str) -> None:
        super().__init__(error_code)
        self.error_code = error_code


def _normalize_path(raw_path: str) -> str:
    path = unicodedata.normalize("NFC", raw_path.replace("\\", "/"))
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in path):
        raise _InvalidFileSet("invalid_path")
    if not path or path.startswith("/") or path.startswith("//") or path.endswith("/") or _PATH_RULE.match(path):
        raise _InvalidFileSet("invalid_path")
    segments = path.split("/")
    if any(not segment or segment in {".", ".."} for segment in segments):
        raise _InvalidFileSet("invalid_path")
    if len(path.encode("utf-8")) > 1024:
        raise _InvalidFileSet("invalid_path")
    if any(len(segment.encode("utf-8")) > 255 for segment in segments):
        raise _InvalidFileSet("invalid_path")
    return "/".join(segments)


def _validate_files(request: ChangedFilesRequest) -> list[_ValidatedFile]:
    if not request.files:
        raise _InvalidFileSet("empty_files")
    if len(request.files) > MAX_FILES:
        raise _InvalidFileSet("too_many_files")

    validated: list[_ValidatedFile] = []
    seen: set[str] = set()
    total_bytes = 0
    for item in request.files:
        normalized_path = _normalize_path(item.path)
        if normalized_path in seen:
            raise _InvalidFileSet("duplicate_path")
        seen.add(normalized_path)
        if Path(normalized_path).suffix.lower() in _FORBIDDEN_EXTENSIONS:
            raise _InvalidFileSet("unsupported_file_type")
        try:
            content = item.content.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise _InvalidFileSet("invalid_path") from exc
        if len(content) > MAX_FILE_BYTES:
            raise _InvalidFileSet("file_too_large")
        total_bytes += len(content)
        if total_bytes > MAX_REQUEST_BYTES:
            raise _InvalidFileSet("request_too_large")
        validated.append(_ValidatedFile(normalized_path, content))
    return validated


def _ensure_temp_root() -> Path:
    base = TEMP_ROOT_BASE
    if base.is_symlink():
        raise RuntimeError("temporary base must not be a symlink")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    base.chmod(0o700)
    return base


def _write_request_files(files: list[_ValidatedFile], request_id: str) -> Path:
    base = _ensure_temp_root()
    root = base / request_id
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    root_resolved = root.resolve()
    base_resolved = base.resolve()
    if not root_resolved.is_relative_to(base_resolved):
        raise RuntimeError("temporary root escaped base")

    try:
        for item in files:
            current = root
            parts = item.path.split("/")
            for segment in parts[:-1]:
                current = current / segment
                if current.is_symlink():
                    raise RuntimeError("temporary path component is a symlink")
                current.mkdir(mode=0o700, exist_ok=True)
                current.chmod(0o700)
            target = current / parts[-1]
            if not target.resolve().is_relative_to(root_resolved):
                raise RuntimeError("temporary file escaped root")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(item.content)
        return root
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise


def _write_worker_result(result_path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_RESULT_BYTES:
        payload = {"version": 1, "status": "error", "error_code": "result_invalid"}
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(result_path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)


def _mask_secret_match(match: re.Match[str], secret_group: int) -> str:
    if secret_group == 0:
        return "<redacted>"
    start, end = match.span(secret_group)
    if start < 0:
        return "<redacted>"
    relative_start = start - match.start()
    relative_end = end - match.start()
    value = match.group(0)
    return f"{value[:relative_start]}<redacted>{value[relative_end:]}"


def _redact_source_line(line: str) -> str:
    redacted = line.replace("\t", "    ")
    for rule in secrets.SECRET_RULES:
        redacted = rule.pattern.sub(
            lambda match, group=rule.secret_group: _mask_secret_match(match, group),
            redacted,
        )
    cleaned = "".join(
        character
        for character in redacted
        if unicodedata.category(character) not in {"Cc", "Cf"}
    )
    return cleaned if len(cleaned) <= MAX_SNIPPET_CHARS else f"{cleaned[:MAX_SNIPPET_CHARS - 3]}..."


def _redacted_source_location(finding: models.Finding) -> tuple[int | None, int | None, str | None]:
    if finding.line is None:
        return None, None, None
    lines = common.read_text_lines(finding.path, MAX_FILE_BYTES)
    if lines is None or finding.line > len(lines):
        raise ValueError("finding line escaped source")
    return finding.line, finding.line, _redact_source_line(lines[finding.line - 1])


def _safe_finding(
    finding: models.Finding,
    root: Path,
    input_paths: set[str],
    selected_standard: StandardId,
) -> dict[str, Any]:
    if not _RULE_ID.fullmatch(finding.rule_id):
        raise ValueError("invalid rule id")
    if finding.severity not in _SEVERITY_RANK:
        raise ValueError("invalid severity")
    if finding.verification_status not in models.VERIFICATION_STATUSES:
        raise ValueError("invalid verification status")
    if finding.line is not None and (isinstance(finding.line, bool) or finding.line < 1):
        raise ValueError("invalid line")
    try:
        relative = finding.path.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("finding path escaped root") from exc
    if relative not in input_paths:
        raise ValueError("finding path was not provided")
    start_line, end_line, redacted_snippet = _redacted_source_location(finding)
    criteria, criteria_truncated = _criteria_for_rule(finding.rule_id, selected_standard)
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "verification_status": finding.verification_status,
        "title": _remove_control_characters(finding.title, 200, "Security finding"),
        "path": relative,
        "line": finding.line,
        "start_line": start_line,
        "end_line": end_line,
        "redacted_snippet": redacted_snippet,
        "reason": _remove_control_characters(
            finding.description,
            500,
            "The selected rule matched this source location; review the surrounding context.",
        ),
        "recommendation": _remove_control_characters(
            finding.recommendation,
            1000,
            "Review this finding and apply a context-appropriate mitigation.",
        ),
        "criteria": criteria,
        "criteria_truncated": criteria_truncated,
    }


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, str, str, int]:
    return (
        -_SEVERITY_RANK[finding["severity"]],
        finding["rule_id"],
        finding["path"],
        finding["line"] or 0,
    )


def _scan_worker(
    temp_root_value: str,
    result_path_value: str,
    selected_standard: StandardId = DEFAULT_STANDARD_ID,
) -> None:
    root = Path(temp_root_value)
    result_path = Path(result_path_value)
    try:
        common.clear_read_text_cache()
        target = models.TargetConfig(
            name="mcp-request",
            path=root,
            categories=("secrets", "dependencies", "configuration", "code"),
            max_file_size_bytes=MAX_FILE_BYTES,
        )
        files = sorted(
            path
            for path in root.rglob("*")
            if path.is_file() and path != result_path
        )
        input_paths = {path.relative_to(root).as_posix() for path in files}
        raw_findings: list[models.Finding] = []
        for path in files:
            for _category, checker in CHECKS:
                raw_findings.extend(checker(path, target))
        findings = [
            _safe_finding(finding, root, input_paths, selected_standard)
            for finding in raw_findings
            if _rule_matches_standard(finding.rule_id, selected_standard)
        ]
        findings.sort(key=_finding_sort_key)
        findings_truncated = len(findings) > 200
        _write_worker_result(
            result_path,
            {
                "version": 1,
                "status": "ok",
                "findings": findings[:200],
                "findings_truncated": findings_truncated,
            },
        )
    except BaseException:
        try:
            _write_worker_result(
                result_path,
                {"version": 1, "status": "error", "error_code": "scanner_error"},
            )
        except BaseException:
            pass
        raise SystemExit(1)


def _read_worker_result(result_path: Path, input_paths: set[str]) -> tuple[list[ScanFinding], bool] | None:
    try:
        if not result_path.is_file() or result_path.stat().st_size > MAX_RESULT_BYTES:
            return None
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        if payload.get("version") != 1 or payload.get("status") != "ok":
            return None
        raw_findings = payload.get("findings")
        truncated = payload.get("findings_truncated")
        if not isinstance(raw_findings, list) or not isinstance(truncated, bool) or len(raw_findings) > 200:
            return None
        findings: list[ScanFinding] = []
        for item in raw_findings:
            if not isinstance(item, dict) or set(item) != {
                "rule_id", "severity", "verification_status", "title", "path", "line", "recommendation",
                "start_line", "end_line", "redacted_snippet", "reason", "criteria", "criteria_truncated"
            }:
                return None
            if (
                not isinstance(item["rule_id"], str)
                or not _RULE_ID.fullmatch(item["rule_id"])
                or not isinstance(item["path"], str)
                or item["path"] not in input_paths
                or (item["line"] is not None and (isinstance(item["line"], bool) or not isinstance(item["line"], int) or item["line"] < 1))
                or item["start_line"] != item["line"]
                or item["end_line"] != item["line"]
                or (item["line"] is None and item["redacted_snippet"] is not None)
                or (item["line"] is not None and not isinstance(item["redacted_snippet"], str))
            ):
                return None
            findings.append(ScanFinding.model_validate(item, strict=True))
        if findings != sorted(
            findings,
            key=lambda item: (-_SEVERITY_RANK[item.severity], item.rule_id, item.path, item.line or 0),
        ):
            return None
        return findings, truncated
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        return None


def _worker_result_error_code(result_path: Path) -> str:
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        return "result_invalid"
    return (
        "scanner_error"
        if payload == {"version": 1, "status": "error", "error_code": "scanner_error"}
        else "result_invalid"
    )


def _cleanup_temp_root(root: Path | None) -> bool:
    if root is None:
        return True
    try:
        base = TEMP_ROOT_BASE.resolve()
        if not root.resolve().is_relative_to(base):
            return False
        shutil.rmtree(root)
        return not root.exists()
    except OSError:
        return False


async def _stop_worker(process: multiprocessing.Process) -> None:
    if not process.is_alive():
        return
    process.terminate()
    await asyncio.to_thread(process.join, 2.0)
    if process.is_alive():
        process.kill()
        await asyncio.to_thread(process.join)


def _terminate_server_after_cleanup_failure(request_id: str) -> None:
    record = json.dumps(
        {
            "timestamp": time.time(),
            "request_id": request_id,
            "execution_status": "failed",
            "cleanup_status": "failed",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        os.write(2, record + b"\n")
    finally:
        os._exit(70)


async def scan_changed_files(request: ChangedFilesRequest) -> ScanResponse:
    request_id = str(uuid.uuid4())
    file_count = len(request.files)
    try:
        files = _validate_files(request)
    except _InvalidFileSet as exc:
        return _response(
            request_id,
            file_count,
            request.standard,
            execution_status="rejected",
            coverage_status="not_evaluated",
            temporary_source_state="not_created",
            error_code=exc.error_code,
            coverage_gaps=["not_evaluated"],
        )

    if not SCAN_LOCK.acquire(blocking=False):
        return _response(
            request_id,
            file_count,
            request.standard,
            execution_status="busy",
            coverage_status="not_evaluated",
            temporary_source_state="not_created",
            error_code="busy",
            coverage_gaps=["not_evaluated"],
        )

    root: Path | None = None
    process: multiprocessing.Process | None = None
    response: ScanResponse
    try:
        try:
            root = _write_request_files(files, request_id)
            result_path = root / f".result-{uuid.uuid4().hex}.json"
            context = multiprocessing.get_context("spawn")
            process = context.Process(
                target=_scan_worker,
                args=(str(root), str(result_path), request.standard),
            )
            process.start()
            await asyncio.to_thread(process.join, SCAN_TIMEOUT_SECONDS)
            if process.is_alive():
                await _stop_worker(process)
                response = _response(
                    request_id,
                    file_count,
                    request.standard,
                    execution_status="timed_out",
                    coverage_status="not_evaluated",
                    temporary_source_state="deleted",
                    error_code="scan_timeout",
                    coverage_gaps=["not_evaluated"],
                )
            else:
                input_paths = {item.path for item in files}
                parsed = _read_worker_result(result_path, input_paths)
                if process.exitcode != 0:
                    response = _response(
                        request_id,
                        file_count,
                        request.standard,
                        execution_status="failed",
                        coverage_status="not_evaluated",
                        temporary_source_state="deleted",
                        error_code=_worker_result_error_code(result_path),
                        coverage_gaps=["not_evaluated"],
                    )
                elif parsed is None:
                    response = _response(
                        request_id,
                        file_count,
                        request.standard,
                        execution_status="failed",
                        coverage_status="not_evaluated",
                        temporary_source_state="deleted",
                        error_code="result_invalid",
                        coverage_gaps=["not_evaluated"],
                    )
                else:
                    findings, findings_truncated = parsed
                    gaps = list(_COVERAGE_GAPS)
                    if any(Path(item.path).name == "package.json" for item in files):
                        gaps.append("dependency_lockfile_presence_not_evaluated")
                    if findings_truncated:
                        gaps.append("findings_truncated")
                    response = _response(
                        request_id,
                        file_count,
                        request.standard,
                        execution_status="completed",
                        coverage_status="partial",
                        temporary_source_state="deleted",
                        error_code=None,
                        coverage_gaps=gaps,
                        findings=findings,
                        findings_truncated=findings_truncated,
                    )
        except BaseException:
            if process is not None and process.is_alive():
                await _stop_worker(process)
            response = _response(
                request_id,
                file_count,
                request.standard,
                execution_status="failed",
                coverage_status="not_evaluated",
                temporary_source_state="deleted",
                error_code="scanner_error",
                coverage_gaps=["not_evaluated"],
            )
    finally:
        cleaned = not (process is not None and process.is_alive()) and _cleanup_temp_root(root)
        SCAN_LOCK.release()
        if not cleaned:
            _terminate_server_after_cleanup_failure(request_id)
    return response
