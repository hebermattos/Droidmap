#!/usr/bin/env python3
"""Exercise bundled templates with real Nuclei on loopback HTTP fixtures.
Usage: python3 tests/test-nuclei-templates.py /path/to/host/nuclei
No Android device, external target or credentials are used.
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
    '/.svn/entries': '<?xml version="1.0"?><wc-entries><entry name="" kind="dir"/></wc-entries>',
    '/.hg/hgrc': '[paths]\ndefault = https://repository.invalid/project\n',
    '/.npmrc': '//registry.npmjs.org/:_authToken=fixture-not-a-secret\n',
    '/wp-config.php.bak': "<?php define('DB_NAME', 'fixture'); define('DB_PASSWORD', 'fixture-not-a-secret');",
    '/containers/json': '[{"Id":"0123456789abcdef","Image":"fixture:latest","State":"running"}]',
    '/api/v1/namespaces': '{"kind":"NamespaceList","apiVersion":"v1","items":[]}',
    '/_all_dbs': '["_users","_replicator","fixture"]',
    '/phpinfo.php': '<html><title>phpinfo()</title><h1>PHP Version 8.3.0</h1></html>',
    '/nginx_status': 'Active connections: 1\nserver accepts handled requests\n 1 1 1\nReading: 0 Writing: 1 Waiting: 0\n',
    '/actuator/env': '{"propertySources":[{"name":"systemEnvironment","properties":{"FIXTURE":{"value":"******"}}}]}',
    '/jolokia/version': '{"request":{"type":"version"},"value":{"agent":"2.0.0","protocol":"8.0"},"status":200}',
}
original = {'git-head-exposure', 'env-exposure', 'git-config', 'directory-listing',
            'security-headers', 'server-status', 'openapi', 'actuator', 'prometheus'}
additional = {'svn-entries', 'mercurial-config', 'npmrc', 'wordpress-config-backup',
              'cors-credentials', 'docker-containers', 'kubernetes-namespaces',
              'couchdb-databases', 'phpinfo', 'nginx-status', 'actuator-env', 'jolokia-version'}
expected = {'droidmap-' + name for name in original | additional}
json_names = ['docker-containers', 'kubernetes-namespaces', 'couchdb-databases', 'actuator-env', 'jolokia-version']
json_paths = {'/containers/json', '/api/v1/namespaces', '/_all_dbs', '/actuator/env', '/jolokia/version'}
# A single marker or product name must not be sufficient.
near_misses = {
    '/.svn/entries': '<html>Subversion entries</html>',
    '/.hg/hgrc': '[paths]\n# no default repository configured\n',
    '/.npmrc': 'registry=https://registry.npmjs.org/\n',
    '/wp-config.php.bak': "<?php // DB_NAME DB_PASSWORD documentation only",
    '/containers/json': '[{"Image":"fixture:latest","State":"running"}]',
    '/api/v1/namespaces': '{"kind":"Status","apiVersion":"v1","items":[]}',
    '/_all_dbs': '{"error":"unauthorized"}',
    '/phpinfo.php': '<html><title>PHP help</title>PHP Version 8.3.0</html>',
    '/nginx_status': 'Active connections: 1\n',
    '/actuator/env': '{"propertySources":[]}',
    '/jolokia/version': '{"request":{"type":"version"},"value":{"agent":"2.0.0"},"status":200}',
}

class Handler(BaseHTTPRequestHandler):
    mode = 'positive'
    requests = []

    def do_GET(self):
        self.requests.append((self.command, self.path, self.headers.get('Origin')))
        body = fixtures.get(self.path, 'Not found')
        if self.mode == 'generic':
            body = '<html><title>Generic login</title>Sign in</html>'
        elif self.mode == 'near-miss':
            body = near_misses.get(self.path, 'Not found')
        self.send_response({'unauthorized': 401, 'forbidden': 403, 'redirect': 302}.get(self.mode, 200))
        self.send_header('Content-Type', 'application/json' if self.path in json_paths
                         and self.mode not in ('generic', 'wrong-content-type') else 'text/html')
        if self.mode == 'redirect':
            self.send_header('Location', '/redirect-destination-must-not-be-visited')
        if self.headers.get('Origin') and self.mode != 'generic':
            self.send_header('Access-Control-Allow-Origin', '*' if self.mode == 'cors-wildcard' else 'https://droidmap.invalid')
            if self.mode != 'cors-no-credentials':
                self.send_header('Access-Control-Allow-Credentials', 'false' if self.mode == 'near-miss' else 'true')
        if self.mode != 'positive':
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_args):
        pass

if len(sys.argv) != 2:
    raise SystemExit(__doc__)
binary = str(pathlib.Path(sys.argv[1]).resolve())
class FixtureServer(ThreadingHTTPServer):
    request_queue_size = 128

server = FixtureServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory() as runtime:
        common = ['-disable-update-check', '-no-interactsh']
        validation = subprocess.run([binary, '-validate', '-t', str(assets), *common],
                                    cwd=runtime, capture_output=True, text=True, timeout=40)
        assert validation.returncode == 0, validation.stdout + validation.stderr
        print('PASS: real Nuclei template validation', flush=True)
        all_templates = sorted(assets.glob('*.yaml'))
        assert len(all_templates) == len(expected) == 21
        def templates(names):
            return [assets / ('droidmap-' + name + '.yaml') for name in sorted(names)]
        cases = [(mode, all_templates, expected if mode == 'positive' else set())
                 for mode in ['positive', 'generic', 'unauthorized', 'forbidden', 'redirect']]
        cases += [('near-miss', templates(additional), set()),
                  ('cors-wildcard', templates(['cors-credentials']), set()),
                  ('cors-no-credentials', templates(['cors-credentials']), set()),
                  ('wrong-content-type', templates(json_names), set()),
                  ('positive', templates(['git-config']), {'droidmap-git-config'})]
        for mode, selected, wanted in cases:
            Handler.mode = mode
            Handler.requests.clear()
            result = subprocess.run([binary, '-u', f'http://127.0.0.1:{server.server_port}',
                '-t', ','.join(str(p) for p in selected), '-jsonl', '-silent', '-no-color', *common,
                '-concurrency', '2', '-bulk-size', '1', '-timeout', '5', '-retries', '0'],
                cwd=runtime, capture_output=True, text=True, timeout=40)
            assert result.returncode == 0, result.stderr
            matches = {json.loads(line)['template-id'] for line in result.stdout.splitlines() if line.startswith('{')}
            assert matches == wanted, (mode, matches, wanted, result.stderr)
            assert Handler.requests, (mode, 'No requests reached the fixture')
            allowed_paths = set(fixtures) | {'/swagger/v1/swagger.json', '/v3/api-docs'}
            assert all(method == 'GET' and path in allowed_paths for method, path, _ in Handler.requests), Handler.requests
            if mode == 'positive' and len(selected) == 21:
                assert set(fixtures) <= {path for _, path, _ in Handler.requests}
                assert any(origin == 'https://droidmap.invalid' for _, _, origin in Handler.requests)
            print(f'PASS: Nuclei {mode} fixture ({len(matches)} matches)', flush=True)
finally:
    server.shutdown()
    server.server_close()
