"""Reproducible weak-to-hardened lab: python -m demo.lab --verify."""
import argparse
import contextlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading


class LabServer(ThreadingHTTPServer):
    daemon_threads = True
    hardened = False


class Handler(BaseHTTPRequestHandler):
    server_version = 'VulnScanLab'
    sys_version = ''

    def log_message(self, *args):
        pass

    def do_GET(self):
        weak = not self.server.hardened
        body = b''
        status = 200
        if self.path == '/':
            body = b'<title>VulnScan local lab</title><h1>Educational localhost fixture</h1><p>All credentials are dummy values.</p>'
        elif weak and self.path == '/.env':
            body = b'DEMO_PASSWORD=not-a-real-secret\n'
        elif weak and self.path == '/.git/HEAD':
            body = b'ref: refs/heads/demo\n'
        elif self.path == '/.well-known/security.txt':
            body = b'Contact: mailto:security@example.invalid\nExpires: 2030-01-01T00:00:00Z\n'
        else:
            status = 404
        self.send_response(status)
        self.send_header('Content-Type', 'text/html' if self.path == '/' else 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        if self.path == '/':
            self.send_header('Set-Cookie', 'demo_session=dummy; Path=/' + ('; HttpOnly; SameSite=Strict' if not weak else ''))
        if not weak:
            self.send_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Permissions-Policy', 'camera=(), microphone=()')
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def running_lab(port=0, hardened=False):
    server = LabServer(('127.0.0.1', port), Handler)
    server.hardened = hardened
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def verify(outdir):
    from datetime import datetime, timezone
    from engine import finalize
    from models import ScanResult
    from report.compare import compare_scans
    from report.json_export import write_json
    from scanner import __version__, webcheck
    snapshots = []
    Path(outdir).mkdir(parents=True, exist_ok=True)
    with running_lab() as server:
        url = 'http://127.0.0.1:%d/' % server.server_port
        for hardened in (False, True):
            server.hardened = hardened
            mode = 'hardened' if hardened else 'weak'
            stamp = datetime.now(timezone.utc).isoformat()
            result = ScanResult('demo-' + mode, __version__, url, stamp,
                                webs=[webcheck.analyze(url, do_dns=False)],
                                meta={'lab': True, 'description': 'Known local fixture; dummy data only'})
            result.finished = datetime.now(timezone.utc).isoformat()
            finalize(result)
            write_json(result, str(Path(outdir, mode + '.json')))
            snapshots.append(result.to_dict())
    difference = compare_scans(*snapshots)
    Path(outdir, 'comparison.json').write_text(json.dumps(difference, indent=2), encoding='utf-8')
    rows = next(iter(difference['websites'].values()))
    resolved = {r['check_id'] for r in rows['resolved']}
    required = {'exposure./.env', 'exposure./.git/HEAD', 'header.content-security-policy', 'header.framing', 'cookie.demo_session'}
    if not required <= resolved or rows['not_verified']:
        raise RuntimeError('Demo did not establish all expected fixes')
    print('Verified %d resolved observations. HTTP transport remains intentionally unencrypted in this localhost lab.' % len(resolved))
    print('Evidence: ' + str(Path(outdir).resolve()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true', help='Scan both states on the same ephemeral loopback port and verify expected fixes')
    parser.add_argument('--output', default='output/demo')
    parser.add_argument('--mode', choices=['weak', 'hardened'], default='weak')
    parser.add_argument('--port', type=int, default=8899)
    args = parser.parse_args()
    if args.verify:
        verify(args.output)
        return
    server = LabServer(('127.0.0.1', args.port), Handler)
    server.hardened = args.mode == 'hardened'
    print('Educational %s lab: http://127.0.0.1:%d/ (dummy data only)' % (args.mode, server.server_port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
