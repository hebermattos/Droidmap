#!/usr/bin/env python3
"""Run the bundled read-only templates against local positive and negative HTTP fixtures.
Usage: python3 tests/test-nuclei-templates.py /path/to/host/nuclei
No Android device or external target is used.
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

assets = pathlib.Path(__file__).resolve().parents[1] / 'app/src/main/assets/nuclei'
fixtures = {
    '/.git/HEAD': 'ref: refs/heads/main\n',
    '/.git/config': '[core]\n repositoryformatversion = 0\n',
    '/.env': 'DB_PASSWORD=fixture-not-a-secret\n',
    '/': '<html><title>Index of /</title><a href="../">Parent Directory</a></html>',
    '/server-status?auto': 'Total Accesses: 1\nTotal kBytes: 1\nBusyWorkers: 1\n',
    '/openapi.json': '{"openapi":"3.0.0","paths":{}}',
    '/actuator': '{"_links":{"self":{"href":"/actuator"}}}',
    '/metrics': '# HELP fixture_total Fixture\n# TYPE fixture_total counter\nfixture_total 1\n',
}
expected = {f'droidmap-{name}' for name in ['git-head-exposure', 'env-exposure', 'git-config',
    'directory-listing', 'security-headers', 'server-status', 'openapi', 'actuator', 'prometheus']}

class Handler(BaseHTTPRequestHandler):
    mode = 'positive'
    def do_GET(self):
        body = fixtures.get(self.path, 'Not found') if self.mode != 'generic' else '<html><title>Generic login</title></html>'
        self.send_response(401 if self.mode == 'forbidden' else 200)
        self.send_header('Content-Type', 'text/plain')
        if self.mode != 'positive':
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'")
        self.end_headers()
        self.wfile.write(body.encode())
    def log_message(self, *_args):
        pass

server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory() as runtime:
        all_templates = sorted(assets.glob('*.yaml'))
        cases = [(mode, all_templates, expected if mode == 'positive' else set())
                 for mode in ['positive', 'generic', 'forbidden']]
        cases.append(('positive', [assets / 'droidmap-git-config.yaml'], {'droidmap-git-config'}))
        for mode, templates, wanted in cases:
            Handler.mode = mode
            result = subprocess.run([sys.argv[1], '-u', f'http://127.0.0.1:{server.server_port}',
                '-t', ','.join(str(p) for p in templates), '-jsonl', '-silent', '-no-color', '-disable-update-check',
                '-no-interactsh', '-timeout', '2', '-retries', '0'],
                cwd=runtime, capture_output=True, text=True, timeout=40)
            assert result.returncode == 0, result.stderr
            matches = {json.loads(line)['template-id'] for line in result.stdout.splitlines() if line.startswith('{')}
            assert matches == wanted, (mode, matches, result.stderr)
            print(f'PASS: Nuclei {mode} fixture ({len(matches)} matches)')
finally:
    server.shutdown()
    server.server_close()
