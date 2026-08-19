from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


StandardId = Literal[
    "sw-dev-security-49",
    "cwe-top-25-2025",
    "owasp-top-10-2025",
    "owasp-asvs-5",
    "owasp-proactive-controls",
    "sw-dev-security-7-types",
    "kisa-secure-coding-guide",
]


def _utf8_size(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("value must be valid UTF-8") from exc


class GuidanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    task_summary: str = Field(min_length=1)
    language: Literal["ko", "en"] = "ko"
    standard: StandardId = "sw-dev-security-49"

    @field_validator("task_summary")
    @classmethod
    def validate_task_summary(cls, value: str) -> str:
        if "\x00" in value or _utf8_size(value) > 2000:
            raise ValueError("task_summary must be 1-2000 UTF-8 bytes without NUL")
        return value


class ChangedFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    path: str
    content: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("content must not contain NUL")
        _utf8_size(value)
        return value


class ChangedFilesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    files: list[ChangedFile]
    standard: StandardId = "sw-dev-security-49"


class LocalizedLabels(BaseModel):
    model_config = ConfigDict(extra="forbid")

    en: str
    ko: str


class StandardLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    labels: LocalizedLabels
    url: str


class StandardReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    standard_id: str
    labels: LocalizedLabels
    issuer: LocalizedLabels
    published_on: str
    version: str
    references: list[StandardLink]


class StandardCriterion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    standard_id: str
    criterion_id: str = Field(description="Official control ID when direct, otherwise the exact related category ID")
    criterion_labels: LocalizedLabels
    mapping_kind: Literal["direct_control", "related_category"] = Field(
        description="direct_control is a detector-to-control mapping; related_category is contextual only"
    )
    category_id: str
    category_labels: LocalizedLabels
    control_id: str | None
    guide_id: str | None
    cwe_ids: list[str]
    support_level: Literal["partial", None]


class GuidanceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    title: str
    recommendation: str
    criteria: list[StandardCriterion] = Field(description="Mapped criteria ordered with direct controls first")
    criteria_truncated: bool = Field(description="True when lower-priority related mappings were omitted")


class GuidanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["koda-advisory-1"] = "koda-advisory-1"
    advisory_only: Literal[True] = True
    blocking: Literal[False] = False
    selected_standard: StandardId
    items: list[GuidanceItem]
    standard_references: list[StandardReference] = Field(description="Edition and primary-source metadata for criteria")
    mapping_notice: Literal["rule_mapping_not_formal_compliance"] = Field(
        default="rule_mapping_not_formal_compliance",
        description="Mappings support explanation and are not a formal violation or compliance decision",
    )
    coverage_notice: str = "static_guidance_not_project_review"


class ScanFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    verification_status: Literal["confirmed", "needs_review", "unverified"]
    title: str
    path: str
    line: int | None
    recommendation: str
    criteria: list[StandardCriterion] = Field(description="Mapped criteria ordered with direct controls first")
    criteria_truncated: bool = Field(description="True when lower-priority related mappings were omitted")


class ScanEngine(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mcp_server_version: str
    mcp_sdk_version: str
    koda_source_commit: str
    koda_source_tree_sha256: str


class ScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["koda-advisory-1"] = "koda-advisory-1"
    request_id: str
    advisory_only: Literal[True] = True
    blocking: Literal[False] = False
    execution_status: Literal["completed", "rejected", "busy", "timed_out", "failed"]
    coverage_status: Literal["partial", "not_evaluated"]
    selected_standard: StandardId
    received_file_count: int
    findings_truncated: bool
    temporary_source_state: Literal["not_created", "deleted"]
    error_code: Literal[
        "empty_files",
        "too_many_files",
        "duplicate_path",
        "invalid_path",
        "unsupported_file_type",
        "file_too_large",
        "request_too_large",
        "busy",
        "scan_timeout",
        "scanner_error",
        "result_invalid",
        None,
    ]
    coverage_gaps: list[str]
    findings: list[ScanFinding]
    standard_references: list[StandardReference] = Field(description="Edition and primary-source metadata for criteria")
    mapping_notice: Literal["rule_mapping_not_formal_compliance"] = Field(
        default="rule_mapping_not_formal_compliance",
        description="Mappings support explanation and are not a formal violation or compliance decision",
    )
    engine: ScanEngine
