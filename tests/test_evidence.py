"""Known-result regressions: uncertainty, redirect identity, evidence and comparison."""
import copy
import json
import socket
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from models import ScanResult
from report.compare import compare_websites
from report.insights import assessment
from scanner import webcheck
from scanner.cve import CVEResolver, _kb_lookup


def response(status=200, headers=(), body=b'<title>Fixture</title>'):
    return {'status': status, 'reason': 'Fixture', 'headers': list(headers), 'body': body}


class EvidenceTests(unittest.TestCase):
    def scan(self, fetch=None, url='https://example.com', tls=None):
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]
        def default_fetch(url, *args, **kwargs):
            return response() if url == 'https://example.com' else response(404)
        with mock.patch.object(socket, 'getaddrinfo', return_value=answer), \
             mock.patch.object(webcheck, 'fetch', side_effect=fetch or default_fetch), \
             mock.patch.object(webcheck, 'tls_info', return_value=tls or {'valid': True, 'legacy_status': 'no_issue'}):
            return webcheck.analyze(url, do_dns=False)

    def test_timeout_is_failed_not_clean(self):
        def fetch(url, *args, **kwargs):
            if url.endswith('/.env'): raise TimeoutError('fixture timeout')
            return response() if url == 'https://example.com' else response(404)
        w = self.scan(fetch)
        checks = {c['id']: c for c in w.checks}
        self.assertEqual(checks['exposure./.env']['status'], 'failed')
        result = ScanResult('id', '2', w.url, 'now', webs=[w])
        self.assertEqual(assessment(result)['status'], 'incomplete')
        self.assertIsNone(assessment(result)['aggregate_risk_indicator'])

    def test_http_error_skips_browser_checks(self):
        w = self.scan(lambda *a, **k: response(403))
        checks = {c['id']: c['status'] for c in w.checks}
        self.assertEqual(checks['http.response'], 'failed')
        self.assertEqual(checks['header.content-security-policy'], 'skipped')
        self.assertNotIn('Content-Security-Policy missing', [f.title for f in w.findings])

    def test_exposure_never_retains_secret_body(self):
        def fetch(url, *args, **kwargs):
            return response(body=b'API_SECRET=fixture-never-retain-9944') if url.endswith('/.env') else response(404)
        w = self.scan(fetch)
        raw = json.dumps(ScanResult('id', '2', w.url, 'now', webs=[w]).to_dict())
        self.assertNotIn('fixture-never-retain-9944', raw)
        item = next(f for f in w.findings if f.check_id == 'exposure./.env')
        self.assertEqual(item.evidence['http_status'], 200)
        self.assertTrue(item.observed_at)
        self.assertEqual(item.evidence['url'], 'https://example.com/.env')

    def test_tls_uses_final_redirect_hostname(self):
        def fetch(url, *args, **kwargs):
            if url == 'https://example.com': return response(301, [('Location', 'https://www.example.com/')])
            return response() if url == 'https://www.example.com/' else response(404)
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]
        with mock.patch.object(socket, 'getaddrinfo', return_value=answer), \
             mock.patch.object(webcheck, 'fetch', side_effect=fetch), \
             mock.patch.object(webcheck, 'tls_info', return_value={'valid': True, 'legacy_status': 'no_issue'}) as tls:
            w = webcheck.analyze('https://example.com', do_dns=False)
        tls.assert_called_once_with('www.example.com', 443, 6.0, public_only=False)
        self.assertEqual(w.final_url, 'https://www.example.com/')

    def test_redirect_loop_and_foreign_host_are_incomplete(self):
        for location in ('https://example.com', 'https://other.example/'):
            w = self.scan(lambda *a, **k: response(301, [('Location', location)]))
            self.assertTrue(w.error)
            self.assertEqual(w.checks[0]['status'], 'failed')

    def test_unknown_tls_result_is_failed(self):
        w = self.scan(tls={'valid': None, 'error': 'timeout'})
        states = {c['id']: c['status'] for c in w.checks}
        self.assertEqual(states['tls.certificate'], 'failed')
        self.assertEqual(states['tls.legacy'], 'failed')

    def test_cve_query_keeps_openssh_patch_update(self):
        with tempfile.TemporaryDirectory() as folder:
            r = CVEResolver(folder)
            data = mock.MagicMock()
            data.__enter__.return_value.read.return_value = b'{"vulnerabilities":[]}'
            with mock.patch('urllib.request.urlopen', return_value=data) as open_url:
                self.assertEqual(r._nvd_query('openbsd', 'openssh', '9.3p2'), [])
            from urllib.parse import parse_qs, urlsplit
            query = parse_qs(urlsplit(open_url.call_args.args[0].full_url).query)
            self.assertIn(':9.3:p2:', query['virtualMatchString'][0])
            self.assertIsNone(r._nvd_query('vendor', 'product', '9.3-vendor-unknown'))
        self.assertFalse(any(v.cve_id == 'CVE-2023-38408' for v in _kb_lookup('OpenSSH', '8.2p1')))
        self.assertTrue(_kb_lookup('Microsoft IIS', '6.0'))
        self.assertEqual(_kb_lookup('OpenSSH', '8.2-vendor99'), [])
        with tempfile.TemporaryDirectory() as folder:
            r = CVEResolver(folder)
            with mock.patch.object(r, '_nvd_query') as query:
                r.lookup('OpenSSH', '8.2-vendor99')
                query.assert_not_called()
                self.assertTrue(r.online)

    def test_cookie_values_are_absent(self):
        w = self.scan(lambda *a, **k: response(headers=[('Set-Cookie', 'session=never-store-this; HttpOnly')]))
        self.assertNotIn('never-store-this', json.dumps(w.__dict__, default=lambda v: v.__dict__))


class ComparisonTests(unittest.TestCase):
    def fixture(self):
        return {'hosts': [], 'webs': [{'url':'https://example.com', 'status':200,
            'findings':[{'title':'CSP missing','severity':'low','check_id':'header.csp'}],
            'checks':[{'id':'header.csp','status':'issue'}], 'vulns':[]} ]}

    def test_resolved_requires_successful_matching_check(self):
        old = self.fixture()
        for status, expected in [('no_issue', 'resolved'), ('failed', 'not_verified'), ('skipped', 'not_verified'), ('issue', 'not_verified')]:
            new = copy.deepcopy(old); new['webs'][0]['findings'] = []; new['webs'][0]['checks'][0]['status'] = status
            self.assertEqual(len(compare_websites(old, new)['https://example.com/'][expected]), 1)

    def test_missing_target_interrupted_and_legacy_are_unknown(self):
        old = self.fixture()
        for new in ({'webs':[]}, {'webs':[{'url':'https://example.com/', 'status':200}]},
                    {'meta':{'interrupted':True},'webs':[{'url':'https://example.com/', 'status':200,'checks':[{'id':'header.csp','status':'no_issue'}]}]}):
            self.assertEqual(len(compare_websites(old, new)['https://example.com/']['not_verified']), 1)

    def test_cve_disappearance_is_not_patch_verification(self):
        old = self.fixture(); old['webs'][0]['vulns'] = [{'cve_id':'CVE-DEMO','severity':'high'}]
        new = copy.deepcopy(old); new['webs'][0]['vulns'] = []
        rows = compare_websites(old,new)['https://example.com/']
        self.assertEqual(rows['not_verified'][0]['title'], 'CVE-DEMO')
        self.assertEqual(len(rows['still_present']), 1)

    def test_multiple_findings_per_check_are_preserved(self):
        old = self.fixture()
        old['webs'][0]['findings'].append({'title':'Second independent observation','check_id':'header.csp','severity':'medium'})
        rows = compare_websites(old, old)['https://example.com/']
        self.assertEqual(len(rows['still_present']), 2)

    def test_browser_and_cli_comparison_contract_agree(self):
        node = os.environ.get('NODE_BINARY') or shutil.which('node')
        if not node:
            self.skipTest('Node is unavailable for browser contract verification')
        old = self.fixture()
        for outcome in ('no_issue','failed','skipped','issue'):
            new = copy.deepcopy(old)
            new['webs'][0]['url'] = 'https://example.com/'
            new['webs'][0]['findings'] = []
            new['webs'][0]['checks'][0]['status'] = outcome
            result = subprocess.run([node, str(Path(__file__).with_name('compare_contract.cjs'))],
                input=json.dumps({'oldScan':old,'newScan':new}), text=True, capture_output=True, check=True, timeout=10)
            self.assertEqual(json.loads(result.stdout), compare_websites(old,new))

    def test_before_after_lab_known_fixes(self):
        from demo.lab import verify
        with tempfile.TemporaryDirectory() as folder:
            verify(folder)
            comparison = json.loads(Path(folder, 'comparison.json').read_text())
            rows = next(iter(comparison['websites'].values()))
            self.assertGreaterEqual(len(rows['resolved']), 5)
            self.assertTrue(any(r['check_id'] == 'http.transport' for r in rows['still_present']))


if __name__ == '__main__':
    unittest.main()
