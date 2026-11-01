import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile

from report.insights import assessment
from report.writer import write_reports
from tests.report_fixture import sample_result


class InsightTests(unittest.TestCase):
    def test_chart_totals_and_priorities_match_evidence(self):
        a = assessment(sample_result())
        self.assertEqual(len(a['observations']), 6)
        self.assertEqual(sum(sum(r['values']) for r in a['charts'][0]['rows']), 6)
        self.assertEqual(sum(sum(r['values']) for r in a['charts'][1]['rows']), 6)
        self.assertEqual(a['charts'][2]['rows'][0]['values'], [1])
        self.assertEqual(a['highest_observation_severity'], 'high')
        self.assertEqual(a['non_informational_observations'], 5)
        self.assertTrue(all(o['why_it_matters'] and o['how_to_verify'] for o in a['observations']))

    def test_zero_findings_and_missing_response_are_not_safety_claims(self):
        r = sample_result()
        r.webs[0].findings = []; r.webs[0].vulns = []
        a = assessment(r)
        self.assertEqual(a['non_informational_observations'], 0)
        self.assertIn('not a security guarantee', a['conclusion'])
        r.webs[0].status = None
        a = assessment(r)
        self.assertEqual(a['status'], 'incomplete')
        self.assertIsNone(a['aggregate_risk_indicator'])
        self.assertEqual(a['charts'][2]['rows'][1]['values'], [1])

    def test_action_group_preserves_all_affected_assets(self):
        import copy
        r = sample_result(); second = copy.deepcopy(r.webs[0]); second.url = 'https://second.example'
        r.webs.append(second)
        a = assessment(r)
        self.assertEqual(len(a['actions'][0]['assets']), 2)
        self.assertEqual(len(a['observations']), 12)

    def test_all_exports_keep_full_evidence_and_explanations(self):
        r = sample_result()
        r.webs[0].findings[0].detail = '<script>alert(1)</script> ' + 'long evidence ' * 100 + ' EVIDENCE-END'
        r.webs[0].vulns[0].description = 'full CVE description ' * 80 + ' CVE-END'
        with tempfile.TemporaryDirectory() as folder:
            files, notes = write_reports(r, folder, ['json','html','docx','pdf'])
            self.assertFalse(notes)
            with open(files['json'],encoding='utf-8') as stream: data = json.load(stream)
            self.assertEqual(data['assessment'], assessment(r))
            with open(files['html'],encoding='utf-8') as stream: html = stream.read()
            self.assertIn('&lt;script&gt;', html)
            self.assertNotIn('<script>alert(1)</script>', html)
            self.assertEqual(html.count('role="img"'), 3)
            with zipfile.ZipFile(files['docx']) as doc:
                for name in doc.namelist(): ET.fromstring(doc.read(name))
                xml = doc.read('word/document.xml').decode()
                for phrase in ('EVIDENCE-END','CVE-END','Why it matters','How to verify','security.txt'):
                    self.assertIn(phrase, xml)
                    self.assertIn(phrase, html)
