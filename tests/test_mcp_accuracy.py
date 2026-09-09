from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from koda_core.models import Finding
from koda_mcp import _worker, scan_service
from koda_mcp.contracts import ChangedFile, ChangedFilesRequest


class MCPAccuracyTests(unittest.TestCase):
    def scan(self, path, content):
        with tempfile.TemporaryDirectory() as directory:
            previous = scan_service.TEMP_ROOT_BASE
            scan_service.TEMP_ROOT_BASE = Path(directory) / 'requests'
            try:
                return asyncio.run(scan_service.scan_changed_files(ChangedFilesRequest(
                    files=[ChangedFile(path=path, content=content)], standard='all',
                )))
            finally:
                scan_service.TEMP_ROOT_BASE = previous

    def test_unsupported_code_type_names_the_file_and_scope(self):
        result = self.scan('app.svelte', '<script>eval(request.query.code)</script>\npassword = "synthetic-secret-123"')
        self.assertEqual('completed', result.execution_status)
        self.assertEqual([{'path': 'app.svelte', 'scope': scope,
                           'reason': 'unsupported_text_file_type'}
                          for scope in ('code', 'secrets', 'configuration_text')],
                         [item.model_dump() for item in result.unevaluated_files])
        self.assertIn('dependency_cve_not_evaluated', result.coverage_gaps)

    def test_supported_config_text_does_not_claim_secret_checks_skipped(self):
        result = self.scan('app.yaml', 'password: "synthetic-secret-123"')
        self.assertEqual(['code'], [item.scope for item in result.unevaluated_files])
        self.assertIn('secret.generic-assignment', {item.rule_id for item in result.findings})

    def test_long_line_reports_all_checks_skipped_for_exact_file(self):
        result = self.scan('app.js', '//' + 'x' * 2001 + '\neval(request.query.code)')
        self.assertEqual([{'path': 'app.js', 'scope': 'all_checks',
                           'reason': 'line_length_limit'}],
                         [item.model_dump() for item in result.unevaluated_files])
        self.assertFalse(result.findings)

    def test_verification_reason_is_preserved_and_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'app.py'
            source.write_text('pass\n')
            finding = Finding(rule_id='code.command-injection', category='code', severity='high',
                              title='Candidate', path=source, line=1, description='Generic description',
                              verification_status='needs_review',
                              verification_note='Specific local limit; password="synthetic-secret-123"')
            result = _worker._safe_finding(finding, root, {'app.py'}, 'all')
            self.assertIn('Specific local limit', result['reason'])
            self.assertNotIn('synthetic-secret-123', result['reason'])
            self.assertIn('<redacted>', result['reason'])

    def test_real_findings_over_output_limit_are_explicit(self):
        result = self.scan('app.py', '\n'.join('eval(input())' for _ in range(201)))
        self.assertEqual('completed', result.execution_status)
        self.assertEqual(200, len(result.findings))
        self.assertTrue(result.findings_truncated)
        self.assertIn('findings_truncated', result.coverage_gaps)


if __name__ == '__main__':
    unittest.main()
