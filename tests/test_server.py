from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from mcp.client import Client

from koda_mcp.server import (
    AuthConfig,
    TokenRecord,
    _LazyConfiguredApp,
    _build_mcp_server,
    _match_token,
    create_app,
    load_config,
)


ROOT = Path(__file__).resolve().parents[1]


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.token = "koda-test-token-256-bit-placeholder-value-123456"
        self.token_digest = hashlib.sha256(self.token.encode("utf-8")).hexdigest()
        self.config_path = self.root / "koda_mcp.json"
        self._write_config(
            tokens=[{"id": "test-client", "token_sha256": self.token_digest, "enabled": True}],
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _write_config(
        self,
        *,
        tokens: list[dict[str, Any]],
        allowed_origins: list[str] | None = None,
        path: Path | None = None,
    ) -> Path:
        target = path or self.config_path
        if target.exists():
            os.chmod(target, 0o600)
        target.write_text(
            json.dumps(
                {
                    "public_host": "koda-mcp.internal.example",
                    "allowed_origins": allowed_origins or ["https://openwebui.internal.example"],
                    "tokens": tokens,
                }
            ),
            encoding="utf-8",
        )
        os.chmod(target, 0o400)
        return target

    def _scope(self, method: str, path: str, headers: list[tuple[bytes, bytes]], body: bytes = b"") -> dict[str, Any]:
        return {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "client": ("127.0.0.1", 1234),
            "server": ("koda-mcp.internal.example", 443),
        }

    async def _call(self, app: Any, scope: dict[str, Any], body: bytes = b"") -> tuple[list[dict[str, Any]], int]:
        messages: list[dict[str, Any]] = []
        receives = 0
        delivered = False

        async def receive() -> dict[str, Any]:
            nonlocal receives, delivered
            receives += 1
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            messages.append(message)

        await app(scope, receive, send)
        status = next(message["status"] for message in messages if message["type"] == "http.response.start")
        return messages, receives if status else receives

    async def _call_with_lifespan(self, app: Any, scope: dict[str, Any], body: bytes = b"") -> tuple[list[dict[str, Any]], int]:
        import asyncio as _asyncio

        events: _asyncio.Queue[dict[str, Any]] = _asyncio.Queue()
        sent: list[dict[str, Any]] = []
        startup_complete = _asyncio.Event()

        async def lifespan_receive() -> dict[str, Any]:
            return await events.get()

        async def lifespan_send(message: dict[str, Any]) -> None:
            sent.append(message)
            if message.get("type") == "lifespan.startup.complete":
                startup_complete.set()

        await events.put({"type": "lifespan.startup"})
        task = _asyncio.create_task(
            app({"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.3"}}, lifespan_receive, lifespan_send)
        )
        await startup_complete.wait()
        result = await self._call(app, scope, body)
        await events.put({"type": "lifespan.shutdown"})
        await task
        return result

    def test_health_is_unauthenticated(self) -> None:
        app = create_app(self.config_path)
        messages, _ = asyncio.run(self._call(app, self._scope("GET", "/healthz", [])))
        self.assertEqual(next(message["status"] for message in messages if message["type"] == "http.response.start"), 200)

    def test_missing_auth_rejects_before_body_receive(self) -> None:
        app = create_app(self.config_path)
        messages, receives = asyncio.run(
            self._call(
                app,
                self._scope("POST", "/mcp", [(b"host", b"koda-mcp.internal.example")]),
                b"sentinel-body",
            )
        )
        self.assertEqual(next(message["status"] for message in messages if message["type"] == "http.response.start"), 401)
        self.assertEqual(receives, 0)
        response_headers = next(message["headers"] for message in messages if message["type"] == "http.response.start")
        self.assertIn((b"www-authenticate", b"Bearer"), response_headers)

    def test_malformed_invalid_and_disabled_tokens_reject_before_body(self) -> None:
        base_app = create_app(self.config_path)
        cases = [b"Basic invalid", b"Bearer", b"Bearer invalid-token"]
        for authorization in cases:
            messages, receives = asyncio.run(
                self._call(
                    base_app,
                    self._scope(
                        "POST",
                        "/mcp",
                        [(b"host", b"koda-mcp.internal.example"), (b"authorization", authorization)],
                    ),
                    b"sentinel-body",
                )
            )
            self.assertEqual(next(message["status"] for message in messages if message["type"] == "http.response.start"), 401)
            self.assertEqual(receives, 0)

        disabled_token = "disabled-token"
        self._write_config(
            tokens=[
                {"id": "enabled", "token_sha256": self.token_digest, "enabled": True},
                {
                    "id": "disabled",
                    "token_sha256": hashlib.sha256(disabled_token.encode()).hexdigest(),
                    "enabled": False,
                },
            ]
        )
        disabled_app = create_app(self.config_path)
        messages, receives = asyncio.run(
            self._call(
                disabled_app,
                self._scope(
                    "POST",
                    "/mcp",
                    [
                        (b"host", b"koda-mcp.internal.example"),
                        (b"authorization", f"Bearer {disabled_token}".encode()),
                    ],
                ),
                b"sentinel-body",
            )
        )
        self.assertEqual(next(message["status"] for message in messages if message["type"] == "http.response.start"), 401)
        self.assertEqual(receives, 0)

    def test_missing_token_cannot_match_placeholder_digest(self) -> None:
        config = AuthConfig(
            public_host="koda-mcp.internal.example",
            allowed_origins=("https://openwebui.internal.example",),
            tokens=(TokenRecord("placeholder", "0" * 64, True),),
        )
        self.assertIsNone(_match_token(config, None))

    def test_host_and_origin_are_checked_after_authentication(self) -> None:
        app = create_app(self.config_path)
        auth = (b"authorization", f"Bearer {self.token}".encode("ascii"))
        wrong_host_scope = self._scope("POST", "/mcp", [(b"host", b"other.example"), auth])
        messages, _ = asyncio.run(self._call(app, wrong_host_scope, b"{}"))
        self.assertEqual(next(message["status"] for message in messages if message["type"] == "http.response.start"), 421)

        wrong_origin_scope = self._scope(
            "POST",
            "/mcp",
            [(b"host", b"koda-mcp.internal.example"), auth, (b"origin", b"null")],
        )
        messages, _ = asyncio.run(self._call(app, wrong_origin_scope, b"{}"))
        self.assertEqual(next(message["status"] for message in messages if message["type"] == "http.response.start"), 403)

    def test_origin_absent_and_registered_are_allowed_while_other_values_are_rejected(self) -> None:
        auth = (b"authorization", f"Bearer {self.token}".encode("ascii"))
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode()
        base_headers = [
            (b"host", b"koda-mcp.internal.example"),
            auth,
            (b"content-type", b"application/json"),
            (b"accept", b"application/json, text/event-stream"),
        ]
        for origin in (None, b"https://openwebui.internal.example"):
            headers = [*base_headers, *(([(b"origin", origin)]) if origin is not None else [])]
            messages, _ = asyncio.run(
                self._call_with_lifespan(create_app(self.config_path), self._scope("POST", "/mcp", headers), body)
            )
            self.assertEqual(next(message["status"] for message in messages if message["type"] == "http.response.start"), 200)

        for origin in (b"null", b"*", b"http://openwebui.internal.example", b"https://unregistered.example"):
            messages, receives = asyncio.run(
                self._call(create_app(self.config_path), self._scope("POST", "/mcp", [*base_headers, (b"origin", origin)]), body)
            )
            self.assertEqual(next(message["status"] for message in messages if message["type"] == "http.response.start"), 403)
            self.assertEqual(receives, 0)

    def test_tokens_are_not_written_to_request_log(self) -> None:
        app = create_app(self.config_path)
        auth = (b"authorization", f"Bearer {self.token}".encode("ascii"))
        secret = "request-log-sentinel-secret"
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "koda_scan_changed_files",
                    "arguments": {"files": [{"path": "auth.py", "content": f'password = "{secret}"\n'}]},
                },
            }
        ).encode("utf-8")
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            messages, _ = asyncio.run(
                self._call_with_lifespan(
                    app,
                    self._scope(
                        "POST",
                        "/mcp",
                        [
                            (b"host", b"koda-mcp.internal.example"),
                            auth,
                            (b"origin", b"https://openwebui.internal.example"),
                            (b"content-type", b"application/json"),
                            (b"accept", b"application/json, text/event-stream"),
                        ],
                    ),
                    body,
                )
            )
        status = next(message["status"] for message in messages if message["type"] == "http.response.start")
        self.assertLess(status, 500)
        self.assertNotIn(self.token, stream.getvalue())
        self.assertNotIn(self.token_digest, stream.getvalue())
        self.assertNotIn(secret, stream.getvalue())
        response_body = b"".join(
            message.get("body", b"") for message in messages if message["type"] == "http.response.body"
        ).decode("utf-8")
        self.assertNotIn(secret, response_body)
        self.assertNotIn('"evidence"', response_body)
        self.assertIn('"redacted_snippet"', response_body)
        self.assertIn("<redacted>", response_body)
        self.assertNotIn("traceback", response_body.casefold())

    def test_tools_have_exact_contract_and_in_memory_guidance_works(self) -> None:
        server = _build_mcp_server()
        tools = asyncio.run(server.list_tools())
        self.assertEqual({tool.name for tool in tools}, {"koda_get_security_guidance", "koda_scan_changed_files"})
        for tool in tools:
            self.assertIsNotNone(tool.output_schema)
            self.assertIn("criteria", tool.description)
            self.assertFalse(tool.input_schema.get("additionalProperties", True))
            self.assertEqual(tool.input_schema["properties"]["standard"]["default"], "sw-dev-security-49")
            self.assertIn('"all"', json.dumps(tool.input_schema))
        scan_tool = next(tool for tool in tools if tool.name == "koda_scan_changed_files")
        self.assertIn("every detected line separately", scan_tool.description)

        async def call() -> Any:
            async with Client(server) as client:
                guidance = await client.call_tool(
                    "koda_get_security_guidance",
                    {"task_summary": "SQL query", "language": "en"},
                )
                scan = await client.call_tool(
                    "koda_scan_changed_files",
                    {"files": [{"path": "demo.py", "content": 'password = "client-sentinel-secret"\n'}]},
                )
                clean_scan = await client.call_tool(
                    "koda_scan_changed_files",
                    {"files": [{"path": "clean.py", "content": "value = 1\n"}]},
                )
                cwe_guidance = await client.call_tool(
                    "koda_get_security_guidance",
                    {"task_summary": "SQL query", "language": "ko", "standard": "cwe-top-25-2025"},
                )
                all_guidance = await client.call_tool(
                    "koda_get_security_guidance",
                    {"task_summary": "SQL query", "language": "ko", "standard": "all"},
                )
                return guidance, scan, clean_scan, cwe_guidance, all_guidance

        guidance_result, scan_result, clean_scan_result, cwe_guidance_result, all_guidance_result = asyncio.run(call())
        self.assertFalse(guidance_result.is_error)
        self.assertTrue(guidance_result.structured_content["advisory_only"])
        guidance_item = next(
            item for item in guidance_result.structured_content["items"] if item["rule_id"] == "code.sql-dynamic-query"
        )
        self.assertTrue(any(item["criterion_id"] == "I-01" for item in guidance_item["criteria"]))
        self.assertFalse(scan_result.is_error)
        self.assertEqual(scan_result.structured_content["execution_status"], "completed")
        self.assertEqual(scan_result.structured_content["selected_standard"], "sw-dev-security-49")
        self.assertEqual(scan_result.structured_content["temporary_source_state"], "deleted")
        self.assertTrue(any(
            criterion["criterion_id"] == "S-06"
            for finding in scan_result.structured_content["findings"]
            for criterion in finding["criteria"]
        ))
        secret_finding = next(
            finding for finding in scan_result.structured_content["findings"]
            if finding["rule_id"] == "secret.generic-assignment"
        )
        self.assertEqual(secret_finding["start_line"], 1)
        self.assertEqual(secret_finding["end_line"], 1)
        self.assertEqual(secret_finding["redacted_snippet"], 'password = "<redacted>"')
        self.assertTrue(secret_finding["reason"])
        self.assertNotIn("client-sentinel-secret", json.dumps(scan_result.structured_content))
        self.assertEqual(json.loads(scan_result.content[0].text), scan_result.structured_content)
        self.assertEqual(clean_scan_result.structured_content["execution_status"], "completed")
        self.assertEqual(clean_scan_result.structured_content["coverage_status"], "partial")
        self.assertEqual(clean_scan_result.structured_content["findings"], [])
        self.assertEqual(cwe_guidance_result.structured_content["selected_standard"], "cwe-top-25-2025")
        self.assertEqual(
            cwe_guidance_result.structured_content["items"][0]["criteria"][0]["standard_id"],
            "cwe-top-25-2025",
        )
        self.assertEqual(all_guidance_result.structured_content["selected_standard"], "all")
        all_item = next(
            item for item in all_guidance_result.structured_content["items"]
            if item["rule_id"] == "code.sql-dynamic-query"
        )
        self.assertFalse(all_item["criteria_truncated"])
        self.assertEqual(
            {criterion["standard_id"] for criterion in all_item["criteria"]},
            {reference["standard_id"] for reference in all_guidance_result.structured_content["standard_references"]},
        )

    def test_config_must_be_owner_readable_only(self) -> None:
        os.chmod(self.config_path, 0o600)
        with self.assertRaises(RuntimeError):
            load_config(self.config_path)

    def test_invalid_startup_configurations_fail_closed(self) -> None:
        missing = self.root / "missing.json"
        with self.assertRaises(RuntimeError):
            load_config(missing)

        malformed = self.root / "malformed.json"
        malformed.write_text("{", encoding="utf-8")
        os.chmod(malformed, 0o400)
        with self.assertRaises(RuntimeError):
            load_config(malformed)

        symlink = self.root / "config-link.json"
        symlink.symlink_to(self.config_path)
        with self.assertRaises(RuntimeError):
            load_config(symlink)

        invalid_cases = [
            [
                {"id": "duplicate", "token_sha256": "1" * 64, "enabled": True},
                {"id": "duplicate", "token_sha256": "2" * 64, "enabled": True},
            ],
            [
                {"id": "one", "token_sha256": "1" * 64, "enabled": True},
                {"id": "two", "token_sha256": "1" * 64, "enabled": True},
            ],
            [{"id": "disabled", "token_sha256": "1" * 64, "enabled": False}],
        ]
        for index, tokens in enumerate(invalid_cases):
            path = self._write_config(tokens=tokens, path=self.root / f"invalid-{index}.json")
            with self.assertRaises(RuntimeError):
                load_config(path)

    def test_missing_config_fails_asgi_startup(self) -> None:
        app = _LazyConfiguredApp(self.root / "missing.json")
        events = [{"type": "lifespan.startup"}]
        sent: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            return events.pop(0)

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        asyncio.run(
            app(
                {"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.3"}},
                receive,
                send,
            )
        )
        self.assertEqual(sent, [{"type": "lifespan.startup.failed", "message": "KODA MCP startup failed"}])

    def test_valid_config_preserves_lifespan_and_health(self) -> None:
        app = _LazyConfiguredApp(self.config_path)
        messages, _ = asyncio.run(self._call_with_lifespan(app, self._scope("GET", "/healthz", [])))
        self.assertEqual(next(message["status"] for message in messages if message["type"] == "http.response.start"), 200)

    def test_raw_body_over_limit_returns_413(self) -> None:
        auth = (b"authorization", f"Bearer {self.token}".encode("ascii"))
        headers = [
            (b"host", b"koda-mcp.internal.example"),
            auth,
            (b"content-type", b"application/json"),
            (b"accept", b"application/json, text/event-stream"),
        ]
        messages, _ = asyncio.run(
            self._call_with_lifespan(
                create_app(self.config_path),
                self._scope("POST", "/mcp", headers),
                b"x" * (8 * 1024 * 1024 + 1),
            )
        )
        self.assertEqual(next(message["status"] for message in messages if message["type"] == "http.response.start"), 413)

    def test_deployment_and_continue_contracts_are_documented(self) -> None:
        compose = (ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8")
        dockerfile = (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
        nginx = (ROOT / "deploy" / "nginx-mcp.conf.example").read_text(encoding="utf-8")
        readme = (ROOT / "README.ko.md").read_text(encoding="utf-8")
        for expected in (
            'platform: linux/amd64',
            'user: "10001:10001"',
            'read_only: true',
            'no-new-privileges:true',
            'mem_limit: 512m',
            'cpus: 1.0',
            'pids_limit: 64',
            'internal: true',
            '127.0.0.1:8766:8766',
        ):
            self.assertIn(expected, compose)
        self.assertIn("python@sha256:72d3d75f2639ab82b34b29390ad3d6e0827c775befee94edda8e9976818f488d", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("location = /mcp", nginx)
        self.assertIn("location = /healthz", nginx)
        self.assertIn("client_max_body_size 8m", nginx)
        self.assertIn("mcpServers:", readme)
        self.assertIn("caBundlePath: <ABSOLUTE_INTERNAL_CA_PATH>", readme)
        self.assertIn("Authorization: Bearer ${{ secrets.KODA_MCP_TOKEN }}", readme)
        self.assertIn("모든 finding을 합치거나 생략하지 말고 각각 별도 절로 출력한다", readme)


if __name__ == "__main__":
    unittest.main()
