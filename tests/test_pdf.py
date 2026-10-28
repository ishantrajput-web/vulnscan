"""Report regression checks for complete evidence and honest incomplete assessments."""
import os
import tempfile
import unittest

from models import Finding
from tests.report_fixture import sample_result

try:
    from pypdf import PdfReader
    from report.pdf_report import write_pdf
except ImportError:
    PdfReader = None


@unittest.skipUnless(PdfReader, 'reportlab/pypdf unavailable')
class PdfTests(unittest.TestCase):
    def render_text(self, result):
        with tempfile.TemporaryDirectory() as folder:
            path = write_pdf(result, os.path.join(folder, 'report.pdf'))
            reader = PdfReader(path)
            self.assertGreaterEqual(len(reader.pages), 5)
            return '\n'.join(page.extract_text() for page in reader.pages)

    def test_complete_report_and_hostile_long_content(self):
        result = sample_result()
        result.webs[0].findings.append(Finding('low','<script>& hostile title', 'Long evidence ' * 900 + ' EVIDENCE-END', 'Long remediation ' * 400 + ' REMEDIATION-END'))
        text = self.render_text(result)
        for expected in ('executive view', 'remediation plan', 'technical evidence', 'Scope, method', 'security.txt', 'EVIDENCE-END', 'REMEDIATION-END', 'CVE-SAMPLE-0001', 'ILLUSTRATIVE SAMPLE'):
            self.assertIn(expected, text)

    def test_failed_target_is_not_a_clean_assessment(self):
        result = sample_result()
        result.webs[0].error = 'Connection refused'
        result.webs[0].findings = []
        result.webs[0].vulns = []
        text = self.render_text(result)
        self.assertIn('INCOMPLETE', text)
        self.assertIn('NOT ASSESSED', text)
        self.assertIn('N/A', text)
        self.assertNotIn('No significant issues were observed', text)
