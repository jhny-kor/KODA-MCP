from __future__ import annotations

import tempfile
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


if __name__ == "__main__":
    unittest.main()
