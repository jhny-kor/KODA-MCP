from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import time
import unicodedata
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import urlsplit

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from .contracts import ChangedFile, ChangedFilesRequest, GuidanceRequest, GuidanceResponse, ScanResponse, StandardId
from .scan_service import get_security_guidance, scan_changed_files


DEFAULT_CONFIG_PATH = Path("/run/secrets/koda_mcp.json")
MAX_CONFIG_BYTES = 64 * 1024
_TOKEN_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class TokenRecord:
    token_id: str
    token_sha256: str
    enabled: bool


@dataclass(frozen=True)
class AuthConfig:
    public_host: str
    allowed_origins: tuple[str, ...]
    tokens: tuple[TokenRecord, ...]


def _is_exact_https_origin(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
        and parsed.path == ""
        and not parsed.query
        and not parsed.fragment
        and "*" not in value
    )


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> AuthConfig:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("KODA MCP auth configuration must be a regular file")
        if metadata.st_size > MAX_CONFIG_BYTES:
            raise RuntimeError("KODA MCP auth configuration is too large")
        if stat.S_IMODE(metadata.st_mode) != 0o400 or metadata.st_uid != os.geteuid():
            raise RuntimeError("KODA MCP auth configuration must be owner-readable mode 0400")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw_document = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise RuntimeError("KODA MCP auth configuration is unavailable") from exc
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if len(raw_document) > MAX_CONFIG_BYTES:
        raise RuntimeError("KODA MCP auth configuration is too large")
    try:
        document = json.loads(raw_document.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("KODA MCP auth configuration is invalid") from exc
    if not isinstance(document, dict):
        raise RuntimeError("KODA MCP auth configuration must be an object")
    if set(document) != {"public_host", "allowed_origins", "tokens"}:
        raise RuntimeError("KODA MCP auth configuration has unknown fields")

    public_host = document.get("public_host")
    allowed_origins = document.get("allowed_origins")
    token_documents = document.get("tokens")
    if (
        not isinstance(public_host, str)
        or not public_host
        or not public_host.isascii()
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in public_host)
        or any(character.isspace() or character in "/?*" for character in public_host)
        or not isinstance(allowed_origins, list)
        or not isinstance(token_documents, list)
    ):
        raise RuntimeError("KODA MCP auth configuration has invalid fields")
    if not allowed_origins or any(
        not isinstance(origin, str) or not _is_exact_https_origin(origin) for origin in allowed_origins
    ):
        raise RuntimeError("KODA MCP allowed_origins must contain exact HTTPS origins")
    if len(set(allowed_origins)) != len(allowed_origins):
        raise RuntimeError("KODA MCP allowed_origins must be unique")

    records: list[TokenRecord] = []
    ids: set[str] = set()
    digests: set[str] = set()
    for document_item in token_documents:
        if not isinstance(document_item, dict):
            raise RuntimeError("KODA MCP token record is invalid")
        if set(document_item) != {"id", "token_sha256", "enabled"}:
            raise RuntimeError("KODA MCP token record has unknown fields")
        token_id = document_item.get("id")
        token_sha256 = document_item.get("token_sha256")
        enabled = document_item.get("enabled")
        if (
            not isinstance(token_id, str)
            or not token_id
            or any(unicoded_character.isspace() for unicoded_character in token_id)
            or not isinstance(token_sha256, str)
            or not _TOKEN_DIGEST.fullmatch(token_sha256)
            or not isinstance(enabled, bool)
        ):
            raise RuntimeError("KODA MCP token record is invalid")
        if token_id in ids or token_sha256 in digests:
            raise RuntimeError("KODA MCP token IDs and digests must be unique")
        ids.add(token_id)
        digests.add(token_sha256)
        records.append(TokenRecord(token_id, token_sha256, enabled))
    if not records or not any(record.enabled for record in records):
        raise RuntimeError("KODA MCP requires at least one enabled token")
    return AuthConfig(public_host, tuple(allowed_origins), tuple(records))


def _header_values(scope: dict[str, Any], name: bytes) -> list[bytes]:
    return [value for key, value in scope.get("headers", []) if key.lower() == name]


def _bearer_token(scope: dict[str, Any]) -> str | None:
    values = _header_values(scope, b"authorization")
    if len(values) != 1:
        return None
    try:
        value = values[0].decode("ascii")
    except UnicodeDecodeError:
        return None
    scheme, separator, token = value.partition(" ")
    if separator != " " or scheme.casefold() != "bearer" or not token or any(character.isspace() for character in token):
        return None
    return token


def _match_token(config: AuthConfig, token: str | None) -> str | None:
    candidate = hashlib.sha256(token.encode("utf-8")).hexdigest() if token is not None else "0" * 64
    matched: str | None = None
    for record in config.tokens:
        equal = hmac.compare_digest(candidate, record.token_sha256)
        if token is not None and equal and record.enabled:
            matched = record.token_id
    return matched


def _json_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


async def _send_json(send: Callable[[dict[str, Any]], Awaitable[None]], status: int, document: dict[str, Any], extra: list[tuple[bytes, bytes]] | None = None) -> None:
    body = _json_bytes(document)
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("ascii"))]
    headers.extend(extra or [])
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _request_metadata(body: bytes) -> tuple[int, int]:
    try:
        document = json.loads(body.decode("utf-8"))
        arguments = document.get("params", {}).get("arguments", {})
        files = arguments.get("files", [])
        if not isinstance(files, list):
            return 0, len(body)
        total = sum(
            len(item.get("content", "").encode("utf-8"))
            for item in files
            if isinstance(item, dict) and isinstance(item.get("content"), str)
        )
        return len(files), total
    except (UnicodeError, json.JSONDecodeError, AttributeError, TypeError, ValueError):
        return 0, len(body)


def _log_request(
    *,
    request_id: str,
    token_id: str,
    file_count: int,
    total_bytes: int,
    execution_status: str,
    severity_counts: Counter[str],
    duration_ms: int,
    cleanup_status: str,
) -> None:
    print(
        json.dumps(
            {
                "timestamp": time.time(),
                "request_id": request_id,
                "token_id": token_id,
                "file_count": file_count,
                "total_bytes": total_bytes,
                "execution_status": execution_status,
                "finding_severity_counts": dict(sorted(severity_counts.items())),
                "duration_ms": duration_ms,
                "cleanup_status": cleanup_status,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        flush=True,
    )


class _ResponseTracker:
    def __init__(self, send: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        self._send = send
        self.status = 500
        self.body = bytearray()

    async def __call__(self, message: dict[str, Any]) -> None:
        if message.get("type") == "http.response.start":
            self.status = int(message.get("status", 500))
        elif message.get("type") == "http.response.body":
            chunk = message.get("body", b"")
            if isinstance(chunk, bytes):
                remaining = 1024 * 1024 - len(self.body)
                if remaining > 0:
                    self.body.extend(chunk[:remaining])
        await self._send(message)


class _AuthenticatedApp:
    def __init__(self, inner: Any, config: AuthConfig) -> None:
        self.inner = inner
        self.config = config

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Awaitable[dict[str, Any]]], send: Callable[..., Awaitable[None]]) -> None:
        if scope.get("type") != "http":
            await self.inner(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "")
        if path == "/healthz":
            if method != "GET":
                await _send_json(send, 405, {"error": "method_not_allowed"})
            else:
                await _send_json(send, 200, {"status": "ok"})
            return
        if path != "/mcp":
            await _send_json(send, 404, {"error": "not_found"})
            return
        if scope.get("query_string", b""):
            await _send_json(send, 400, {"error": "query_not_allowed"})
            return
        host_values = _header_values(scope, b"host")
        try:
            host = host_values[0].decode("ascii") if len(host_values) == 1 else None
        except UnicodeDecodeError:
            host = None
        if host != self.config.public_host:
            await _send_json(send, 421, {"error": "misdirected_request"})
            return
        if method not in {"GET", "POST", "DELETE"}:
            await _send_json(send, 405, {"error": "method_not_allowed"})
            return

        token = _bearer_token(scope)
        token_id = _match_token(self.config, token)
        if token_id is None:
            await _send_json(
                send,
                401,
                {"error": "unauthorized"},
                [(b"www-authenticate", b"Bearer")],
            )
            return

        origin_values = _header_values(scope, b"origin")
        try:
            origin = origin_values[0].decode("utf-8") if origin_values else None
        except UnicodeDecodeError:
            origin = None
        if len(origin_values) > 1 or (origin is not None and origin not in self.config.allowed_origins) or (origin_values and origin is None):
            await _send_json(send, 403, {"error": "origin_not_allowed"})
            return

        request_id = str(uuid.uuid4())
        request_body = bytearray()
        request_size = 0

        async def tracked_receive() -> dict[str, Any]:
            nonlocal request_size
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                if isinstance(chunk, bytes):
                    request_size += len(chunk)
                    remaining = 8 * 1024 * 1024 - len(request_body)
                    if remaining > 0:
                        request_body.extend(chunk[:remaining])
            return message

        tracker = _ResponseTracker(send)
        started = time.monotonic()
        try:
            await self.inner(scope, tracked_receive, tracker)
        finally:
            file_count, total_bytes = _request_metadata(bytes(request_body))
            execution_status = "completed" if tracker.status < 300 else "failed"
            severity_counts: Counter[str] = Counter()
            cleanup_status = "unknown"
            try:
                document = json.loads(bytes(tracker.body).decode("utf-8"))
                structured = document.get("result", {}).get("structuredContent", {})
                execution_status = structured.get("execution_status", execution_status)
                cleanup_status = structured.get("temporary_source_state", cleanup_status)
                for finding in structured.get("findings", []):
                    if isinstance(finding, dict) and isinstance(finding.get("severity"), str):
                        severity_counts[finding["severity"]] += 1
            except (UnicodeError, json.JSONDecodeError, AttributeError, TypeError):
                if request_size > 0:
                    total_bytes = total_bytes or request_size
            _log_request(
                request_id=request_id,
                token_id=token_id,
                file_count=file_count,
                total_bytes=total_bytes,
                execution_status=execution_status,
                severity_counts=severity_counts,
                duration_ms=int((time.monotonic() - started) * 1000),
                cleanup_status=cleanup_status,
            )
            request_body.clear()
            tracker.body.clear()


def _build_mcp_server() -> MCPServer:
    server = MCPServer(
        name="KODA Security Advisory",
        version="0.1.0",
        instructions=(
            "KODA is advisory-only. It evaluates only complete text files supplied by the client "
            "and never reads the developer workspace. Results are partial and non-blocking. "
            "Use sw-dev-security-49 unless the user explicitly requests another supported standard. "
            "Use standard=all only when the user asks for every supported standards mapping; in that mode, preserve "
            "every KODA core finding and list all criteria grouped by standard without omission. "
            "For every finding, render one separate section without grouping or omitting returned findings. "
            "Each section must show path and line range, the redacted_snippet as the problem code, selected-standard "
            "criterion ID and title, reason, verification status, remediation, and a context-appropriate corrected "
            "code example. Never reconstruct text replaced by <redacted>. If findings_truncated is true, say that "
            "additional findings were omitted by the safety limit. Related_category mappings are contextual; never "
            "describe a mapping as formal compliance or a definitive standards violation."
        ),
    )

    @server.tool(name="koda_get_security_guidance", structured_output=True)
    def guidance(
        task_summary: str,
        language: Literal["ko", "en"] = "ko",
        standard: StandardId = "sw-dev-security-49",
    ) -> GuidanceResponse:
        """Return KODA guidance criteria for one standard, or every supported mapping with standard=all."""
        return get_security_guidance(
            GuidanceRequest(task_summary=task_summary, language=language, standard=standard)
        )

    @server.tool(name="koda_scan_changed_files", structured_output=True)
    async def scan(
        files: list[ChangedFile],
        standard: StandardId = "sw-dev-security-49",
    ) -> ScanResponse:
        """Run KODA source checks; return every detected line separately with one standard or all mapped criteria."""
        return await scan_changed_files(ChangedFilesRequest(files=files, standard=standard))

    for tool_name in ("koda_get_security_guidance", "koda_scan_changed_files"):
        tool = server._tool_manager.get_tool(tool_name)
        if tool is None:
            raise RuntimeError(f"MCP tool registration failed: {tool_name}")
        argument_model = tool.fn_metadata.arg_model
        argument_model.model_config = {**argument_model.model_config, "extra": "forbid"}
        argument_model.model_rebuild(force=True)
        tool.parameters = argument_model.model_json_schema(by_alias=True)

    return server


def create_app(config_path: Path = DEFAULT_CONFIG_PATH) -> _AuthenticatedApp:
    config = load_config(config_path)
    server = _build_mcp_server()
    inner = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        max_request_body_size=8 * 1024 * 1024,
        host=config.public_host,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[config.public_host],
            allowed_origins=list(config.allowed_origins),
        ),
    )
    return _AuthenticatedApp(inner, config)


class _LazyConfiguredApp:
    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH) -> None:
        self._config_path = config_path
        self._inner: _AuthenticatedApp | None = None

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Awaitable[dict[str, Any]]], send: Callable[..., Awaitable[None]]) -> None:
        if self._inner is None:
            try:
                self._inner = create_app(self._config_path)
            except Exception:
                if scope.get("type") == "lifespan":
                    message = await receive()
                    if message.get("type") == "lifespan.startup":
                        await send({"type": "lifespan.startup.failed", "message": "KODA MCP startup failed"})
                        return
                raise
        await self._inner(scope, receive, send)


app = _LazyConfiguredApp()
