"""Everything the scan subprocess runs.

This module is the spawn target, so the child interpreter imports exactly what
is here. It deliberately does not import .contracts: pydantic costs more to
import than the whole scan of a typical request, and nothing on this path uses
it. Response models are the parent's concern.
"""
from __future__ import annotations

import json
import os
import re
import unicodedata
from pathlib import Path
from typing import Any

from koda_core import models
from koda_core.checks import code_patterns, common, configuration, dependencies, secrets

from .standard_catalog_data import RULE_STANDARD_MAPPINGS

MAX_FILE_BYTES = 512 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_CRITERIA_PER_RULE = 5
MAX_SNIPPET_CHARS = 500
# One of the StandardId literals; typed as str so this module stays free of
# the pydantic-backed contracts module.
DEFAULT_STANDARD_ID: str = "sw-dev-security-49"
_RULE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SEVERITY_RANK = {severity: index for index, severity in enumerate(models.SEVERITIES)}
CHECKS = (
    ("secrets", secrets.check_file),
    ("dependencies", dependencies.check_file),
    ("configuration", configuration.check_file),
    ("code", code_patterns.check_file),
)
# Detection requires an assignment at line start to limit false positives;
# output redaction also masks the same assignment embedded in a snippet/note.
_GENERIC_SECRET_RULE = next(rule for rule in secrets.SECRET_RULES if rule.rule_id == "secret.generic-assignment")
_INLINE_SECRET_PATTERN = re.compile(_GENERIC_SECRET_RULE.pattern.pattern.replace(r"^\s*", r"(?<!\w)", 1))


def _criteria_for_rule(
    rule_id: str,
    selected_standard: str = DEFAULT_STANDARD_ID,
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


def _rule_matches_standard(rule_id: str, standard_id: str) -> bool:
    return standard_id == "all" or any(
        item["standard_id"] == standard_id for item in RULE_STANDARD_MAPPINGS.get(rule_id, ())
    )


def _remove_control_characters(value: str, limit: int, default: str) -> str:
    cleaned = "".join(
        character
        for character in value
        if unicodedata.category(character) not in {"Cc", "Cf"}
    )[:limit]
    return cleaned or default


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
    redacted = _INLINE_SECRET_PATTERN.sub(
        lambda match: _mask_secret_match(match, _GENERIC_SECRET_RULE.secret_group), redacted,
    )
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
    selected_standard: str,
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
            _redact_source_line(finding.verification_note or finding.description),
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


def _write_worker_result(result_path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_RESULT_BYTES:
        payload = {"version": 1, "status": "error", "error_code": "result_invalid"}
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(result_path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)


def _scan_worker(
    temp_root_value: str,
    result_path_value: str,
    selected_standard: str = DEFAULT_STANDARD_ID,
    unanalyzed_paths: tuple[str, ...] = (),
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
        unanalyzed = set(unanalyzed_paths)
        raw_findings: list[models.Finding] = []
        for path in files:
            # Written to the tree but not scanned: sibling-file checks still see
            # it, while no line rule is handed a line it cannot bound.
            if path.relative_to(root).as_posix() in unanalyzed:
                continue
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
