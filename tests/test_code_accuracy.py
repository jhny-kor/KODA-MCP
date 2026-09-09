from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from koda_core.checks import code_patterns
from koda_core.models import TargetConfig


class CodeAccuracyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.target = TargetConfig(name="test", path=self.root, max_file_size_bytes=524288)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _check(self, name: str, content: str):
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return code_patterns.check_file(path, self.target)

    def test_taint_does_not_cross_function_boundaries(self) -> None:
        findings = self._check(
            "handlers.py",
            "def first(request):\n"
            "    command = request.query[\"cmd\"]\n"
            "def second():\n"
            "    os.system(command)\n",
        )
        self.assertNotIn("code.command-injection", {item.rule_id for item in findings})

    def test_taint_is_confirmed_within_one_function(self) -> None:
        findings = self._check(
            "handler.py",
            "def run(request):\n"
            "    command = request.query[\"cmd\"]\n"
            "    os.system(command)\n",
        )
        self.assertEqual(
            [("code.command-injection", "confirmed")],
            [(item.rule_id, item.verification_status) for item in findings],
        )

    def test_local_reassignment_does_not_confirm_later_function_flow(self) -> None:
        findings = self._check(
            "handlers.py",
            "x = request.query[\"cmd\"]\n"
            "def first():\n"
            "    x = \"fixed\"\n"
            "def second():\n"
            "    subprocess.run(x, shell=True)\n",
        )
        command = [item for item in findings if item.rule_id == "code.command-injection"]
        self.assertEqual(["needs_review"], [item.verification_status for item in command])

    def test_javascript_control_block_keeps_function_taint(self) -> None:
        findings = self._check(
            "handler.js",
            "function run(req) {\n"
            "  const command = req.query.cmd;\n"
            "  if (command) {\n"
            "    eval(command);\n"
            "  }\n"
            "}\n",
        )
        self.assertIn("code.eval-user-input", {item.rule_id for item in findings})

    def test_nested_javascript_function_restores_outer_taint(self) -> None:
        findings = self._check(
            "handler.js",
            "function outer(req) {\n"
            "  const command = req.query.cmd;\n"
            "  function inner() {}\n"
            "  eval(command);\n"
            "}\n",
        )
        self.assertIn("code.eval-user-input", {item.rule_id for item in findings})

    def test_nested_javascript_arrow_restores_outer_taint(self) -> None:
        findings = self._check(
            "handler.js",
            "function outer(req) {\n"
            "  const command = req.query.cmd;\n"
            "  const inner = () => {};\n"
            "  eval(command);\n"
            "}\n",
        )
        self.assertIn("code.eval-user-input", {item.rule_id for item in findings})

    def test_javascript_function_exit_does_not_leak_local_taint(self) -> None:
        findings = self._check(
            "handler.js",
            "const command = \"fixed\";\n"
            "function unused(req) {\n"
            "  const command = req.query.cmd;\n"
            "}\n"
            "eval(command);\n",
        )
        self.assertNotIn("code.eval-user-input", {item.rule_id for item in findings})

    def test_contextual_findings_are_not_capped_at_forty_five(self) -> None:
        findings = self._check("many.py", "\n".join(["os.system(request.query[\"cmd\"])"] * 46) + "\n")
        self.assertEqual(46, sum(item.rule_id == "code.command-injection" for item in findings))

    def test_mybatis_findings_are_not_capped_at_five(self) -> None:
        xml = "<mapper>\n" + "".join(
            f'<select id="q{index}">select * from users where id = ${{id{index}}}</select>\n'
            for index in range(6)
        ) + "</mapper>\n"
        findings = self._check("queries.xml", xml)
        self.assertEqual(6, sum(item.rule_id == "code.sql-dynamic-query" for item in findings))

    def test_jsp_findings_are_not_capped_at_five(self) -> None:
        findings = self._check("page.jsp", "\n".join(["<%= request.getParameter('name') %>"] * 6) + "\n")
        self.assertEqual(6, sum(item.rule_id == "code.xss-dom-sink" for item in findings))

    def test_python_scope_exit_restores_top_level_taint(self) -> None:
        findings = self._check(
            "handlers.py",
            "import os\n"
            "x = \"echo fixed\"\n"
            "def unused(request):\n"
            "    x = request.args[\"cmd\"]\n"
            "subprocess.run(x, shell=True)\n",
        )
        command = [item for item in findings if item.rule_id == "code.command-injection"]
        self.assertEqual(["needs_review"], [item.verification_status for item in command])

    def test_nested_python_scope_exit_restores_outer_taint(self) -> None:
        findings = self._check(
            "handlers.py",
            "def outer(request):\n"
            "    x = request.args[\"cmd\"]\n"
            "    def inner():\n"
            "        x = \"fixed\"\n"
            "    os.system(x)\n",
        )
        command = [item for item in findings if item.rule_id == "code.command-injection"]
        self.assertEqual(["confirmed"], [item.verification_status for item in command])

    def test_all_repeated_candidates_are_returned(self) -> None:
        findings = self._check("app.py", "\n".join(["app = FastAPI()"] * 6) + "\n")
        rate_limit = [item for item in findings if item.rule_id == "code.api-missing-rate-limit"]
        self.assertEqual(6, len(rate_limit))

    def test_library_named_file_is_still_analyzed(self) -> None:
        findings = self._check("lodash-v4.17.21.min.js", "document.write(location.hash)\n")
        self.assertIn("code.xss-dom-sink", {item.rule_id for item in findings})

    def test_global_auth_and_rate_controls_do_not_silence_candidates(self) -> None:
        findings = self._check(
            "server.js",
            "const app = express();\n"
            "app.use(requireAuth);\n"
            "const limiter = rateLimit({ windowMs: 60000 });\n",
        )
        rule_ids = {item.rule_id for item in findings}
        self.assertIn("code.api-missing-rate-limit", rule_ids)

        findings = self._check(
            "routes.js",
            "const app = express();\n"
            "app.use(requireAuth);\n"
            "app.get('/api/admin', (req) => secret(req));\n",
        )
        self.assertIn("code.api-route-missing-auth", {item.rule_id for item in findings})


if __name__ == "__main__":
    unittest.main()
