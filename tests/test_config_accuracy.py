import unittest
import tempfile
from pathlib import Path

from koda_core.checks import configuration, secrets
from koda_core.models import TargetConfig


class ConfigurationAccuracyTests(unittest.TestCase):
    def test_secret_findings_are_not_capped_per_rule(self) -> None:
        path = self.tmp_path / "secrets.py"
        path.write_text("\n".join(f'password = "secret-value-{i:02d}"' for i in range(6)))
        findings = secrets.check_file(path, TargetConfig("t", self.tmp_path))
        self.assertEqual(6, len([f for f in findings if f.rule_id == "secret.generic-assignment"]))

    def test_kubernetes_detection_handles_inline_comments_and_unknown_filename(self) -> None:
        path = self.tmp_path / "workload.yaml"
        path.write_text(
            "apiVersion: apps/v1\nkind: Deployment\nspec:\n"
            "  template:\n    spec:\n      containers:\n"
            "      - name: app\n        securityContext:\n"
            "          privileged: true # reviewed exception\n"
            "          allowPrivilegeEscalation: true # bad\n"
        )
        findings = configuration.check_file(path, TargetConfig("t", self.tmp_path))
        rules = {f.rule_id for f in findings}
        self.assertIn("config.k8s-privileged-container", rules)
        self.assertIn("config.k8s-allow-privilege-escalation", rules)
        self.assertTrue(any(f.evidence == "privileged: true # reviewed exception" for f in findings))

    def test_yaml_comments_and_quoted_booleans_are_handled(self) -> None:
        path = self.tmp_path / "compose.yaml"
        path.write_text('services:\n  app:\n    privileged: true # review\n    privileged: "true"\n    network_mode: host # review\n    label: "text # kept"\n')
        findings = configuration.check_file(path, TargetConfig("t", self.tmp_path))
        self.assertEqual({"config.compose-privileged", "config.compose-host-network"}, {f.rule_id for f in findings})
        self.assertEqual(2, len(findings))
        self.assertTrue(all("# review" in f.evidence for f in findings))

    def test_kubernetes_block_scalar_is_not_scanned_as_structure(self) -> None:
        for indicator in ("|-", ">2", "|2-", "|2+", "|-2", "|+2"):
            path = self.tmp_path / f"plain-{indicator.replace('|', 'p').replace('>', 'g')}.yaml"
            path.write_text(f"apiVersion: v1\nkind: ConfigMap\ndata:\n  note: {indicator}\n    privileged: true\n    allowPrivilegeEscalation: true\n")
            findings = configuration.check_file(path, TargetConfig("t", self.tmp_path))
            self.assertFalse(any(f.rule_id.startswith("config.k8s-") for f in findings), indicator)

    def test_compose_block_scalar_is_not_scanned_as_configuration(self) -> None:
        for indicator in ("|-", ">2", "|2-", "|2+", "|-2", "|+2"):
            path = self.tmp_path / "compose.yaml"
            path.write_text(f"services:\n  app:\n    note: {indicator}\n      privileged: true\n      network_mode: host\n")
            findings = configuration.check_file(path, TargetConfig("t", self.tmp_path))
            self.assertFalse(findings, indicator)

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()
