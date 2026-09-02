from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from koda_core.checks import code_patterns, configuration, dependencies, secrets
from koda_core.models import TargetConfig


class CoreCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.target = TargetConfig(name="test", path=self.root, max_file_size_bytes=524288)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_positive_rules(self) -> None:
        secret_path = self._write("config.py", 'password = "not-a-placeholder-secret"\n')
        code_path = self._write("api.py", 'subprocess.run(request.query["cmd"], shell=True)\n')
        sql_path = self._write("query.py", 'cursor.execute("SELECT * FROM users WHERE id = " + request.args["id"])\n')
        path_path = self._write("files.py", 'open(request.args["path"]).read()\n')
        tls_path = self._write("tls.py", "context.check_hostname = False\n")
        debug_path = self._write(".env", "DEBUG=true\n")
        config_path = self._write("Dockerfile", "FROM python:3.12\n")
        dependency_path = self._write("requirements.txt", "requests\n")

        self.assertIn("secret.generic-assignment", {item.rule_id for item in secrets.check_file(secret_path, self.target)})
        self.assertIn("code.command-injection", {item.rule_id for item in code_patterns.check_file(code_path, self.target)})
        self.assertIn("code.sql-dynamic-query", {item.rule_id for item in code_patterns.check_file(sql_path, self.target)})
        self.assertIn("code.path-traversal", {item.rule_id for item in code_patterns.check_file(path_path, self.target)})
        self.assertIn(
            "code.tls-certificate-verification-disabled",
            {item.rule_id for item in code_patterns.check_file(tls_path, self.target)},
        )
        self.assertIn("config.debug-enabled", {item.rule_id for item in configuration.check_file(debug_path, self.target)})
        self.assertIn("config.docker-no-user", {item.rule_id for item in configuration.check_file(config_path, self.target)})
        self.assertIn(
            "dependency.python-unpinned-requirement",
            {item.rule_id for item in dependencies.check_file(dependency_path, self.target)},
        )

    def test_safe_references_are_not_reported_as_generic_secrets(self) -> None:
        path = self._write("safe.py", 'password = os.getenv("PASSWORD")\n')
        self.assertNotIn("secret.generic-assignment", {item.rule_id for item in secrets.check_file(path, self.target)})

    def test_safe_code_and_pinned_dependencies_are_not_reported(self) -> None:
        code_path = self._write("safe.py", 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n')
        requirements_path = self._write("requirements.txt", "requests==2.32.5\n")
        package_path = self._write("package.json", '{"dependencies":{"demo":"1.0.0"}}')
        self._write("package-lock.json", "{}")
        self.assertNotIn("code.sql-dynamic-query", {item.rule_id for item in code_patterns.check_file(code_path, self.target)})
        self.assertFalse(dependencies.check_file(requirements_path, self.target))
        self.assertNotIn(
            "dependency.node-missing-lockfile",
            {item.rule_id for item in dependencies.check_file(package_path, self.target)},
        )

    def test_persistent_cookie_rule_still_matches(self) -> None:
        path = self._write(
            "cookie.js",
            'res.setHeader("Set-Cookie", `session_token=${t}; Max-Age=31536000`);\n',
        )
        self.assertIn(
            "code.persistent-sensitive-cookie",
            {item.rule_id for item in code_patterns.check_file(path, self.target)},
        )

    def test_null_state_does_not_cross_method_boundaries(self) -> None:
        path = self._write(
            "Cross.java",
            "public class Cross {\n"
            "  public void first() {\n"
            "    String user = null;\n"
            "  }\n"
            "  public void second(String user) {\n"
            "    user.trim();\n"
            "  }\n"
            "}\n",
        )
        self.assertNotIn(
            "code.null-pointer-dereference",
            {item.rule_id for item in code_patterns.check_file(path, self.target)},
        )

    def test_null_state_is_kept_within_one_method(self) -> None:
        path = self._write(
            "Same.java",
            "public class Same {\n"
            "  public void only() {\n"
            "    String user = null;\n"
            "    user.trim();\n"
            "  }\n"
            "}\n",
        )
        findings = [
            item
            for item in code_patterns.check_file(path, self.target)
            if item.rule_id == "code.null-pointer-dereference"
        ]
        self.assertEqual([(4, "confirmed")], [(item.line, item.verification_status) for item in findings])

    def test_nullable_map_field_stays_visible_to_every_method(self) -> None:
        # A Map declaration is as often a field as a local, so the receiver set
        # must survive the method boundary that clears null state.
        path = self._write(
            "Field.java",
            "public class Field {\n"
            "  private Map<String,String> cache = new HashMap<>();\n"
            "  public void useIt(String k) {\n"
            "    cache.get(k).trim();\n"
            "  }\n"
            "}\n",
        )
        self.assertIn(
            "code.null-pointer-dereference",
            {item.rule_id for item in code_patterns.check_file(path, self.target)},
        )

    def test_alias_extensions_are_analyzed_like_their_primary(self) -> None:
        source = (
            "// const bad = eval(req.query.cmd);\n"
            "export function h(req, res) {\n"
            "  app.use(csrf.disable());\n"
            "  jwt.verify(token, key, { verify_signature: false });\n"
            "  document.write(req.query.name);\n"
            "}\n"
        )
        results = {}
        for extension in (".js", ".mjs", ".cjs"):
            path = self._write(f"handler{extension}", source)
            results[extension] = {item.rule_id for item in code_patterns.check_file(path, self.target)}
        # csrf-disabled and jwt-verification-disabled come only from the
        # per-extension line rules, so they catch an alias that selects none.
        self.assertLessEqual(
            {"code.xss-dom-sink", "code.csrf-disabled", "code.jwt-verification-disabled"},
            results[".js"],
        )
        self.assertEqual(results[".js"], results[".mjs"])
        self.assertEqual(results[".js"], results[".cjs"])
        # The commented-out eval must stay suppressed for the aliases too.
        self.assertNotIn("code.eval-user-input", results[".mjs"])

        markup = "<script>document.write(location.hash)</script>\n"
        html = {item.rule_id for item in code_patterns.check_file(self._write("p.html", markup), self.target)}
        htm = {item.rule_id for item in code_patterns.check_file(self._write("p.htm", markup), self.target)}
        self.assertIn("code.xss-dom-sink", html)
        self.assertEqual(html, htm)

    def test_one_long_generated_line_scans_in_bounded_time(self) -> None:
        # A single generated or minified line is an ordinary input well under
        # the 512 KiB file limit, so rules must stay linear in line length.
        # This line names a cookie and a credential but never expires, so the
        # persistent-cookie rule has to reject it the slow way.
        blob = "NOTES = " + ", ".join(
            f'"c{index}: cookie password token"' for index in range(1600)
        ) + "\n"
        path = self._write("generated.py", blob)
        started = time.monotonic()
        code_patterns.check_file(path, self.target)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_many_tracked_java_names_scan_in_bounded_time(self) -> None:
        # Null state is tracked per name, so a wide file must not cost one
        # regex build per (line, tracked name).
        body = ["public class Wide {"]
        for index in range(1200):
            body += [
                f"  Object v{index} = null;",
                f"  v{index}.toString();",
            ]
        body.append("}")
        path = self._write("Wide.java", "\n".join(body))
        started = time.monotonic()
        code_patterns.check_file(path, self.target)
        self.assertLess(time.monotonic() - started, 5.0)


if __name__ == "__main__":
    unittest.main()
