#!/usr/bin/env python3
"""Test the patched host CLI: metadata, endpoint scope, no redirects, strict TLS."""
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading

hits = []
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        hits.append(self.path)
        if self.path == '/':
            self.send_response(302)
            self.send_header('Location', '/must-not-follow')
        else:
            self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><title>Droidmap test</title></html>')
    def log_message(self, *_):
        pass

def run(url, home, trust=None):
    cmd = [sys.argv[1], '-u', url, '-json', '-silent', '-no-color', '-no-stdin',
           '-disable-update-check', '-no-fallback-scheme', '-cdn=false', '-title',
           '-status-code', '-web-server', '-tech-detect', '-location', '-content-type',
           '-response-time', '-tls-grab', '-threads', '1', '-rate-limit', '2',
           '-timeout', '3', '-retries', '0', '-response-size-to-read', '262144',
           '-response-size-to-save', '0']
    env = {k:v for k,v in os.environ.items() if not k.lower().endswith('_proxy')}
    env.update(HOME=home, XDG_CONFIG_HOME=home, XDG_CACHE_HOME=home)
    if trust: env['SSL_CERT_FILE'] = trust
    output = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, cwd=home, timeout=40)
    rows = []
    for line in output.stdout.splitlines():
        try: rows.append(json.loads(line))
        except json.JSONDecodeError: pass
    return rows

with tempfile.TemporaryDirectory() as home:
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_port}/'
    rows = run(url, home)
    assert len(rows) == 1, rows
    assert rows[0]['url'] == url and rows[0]['status_code'] == 302, rows
    assert rows[0]['title'] == 'Droidmap test', rows
    assert '/must-not-follow' not in hits, hits
    server.shutdown(); server.server_close()
    cert, key = str(Path(home)/'cert.pem'), str(Path(home)/'key.pem')
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,
                    '-out',cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    secure = http.server.ThreadingHTTPServer(('127.0.0.1',0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(cert,key)
    secure.socket = tls.wrap_socket(secure.socket, server_side=True)
    threading.Thread(target=secure.serve_forever, daemon=True).start()
    previous = len(hits)
    rows = run(f'https://127.0.0.1:{secure.server_port}/',home)
    assert not any(row.get('status_code',0) >= 100 and not row.get('failed') for row in rows), rows
    assert len(hits) == previous, hits
    trusted = run(f'https://127.0.0.1:{secure.server_port}/',home,cert)
    assert len(trusted) == 1 and trusted[0]['status_code'] == 302, trusted
    assert trusted[0].get('tls',{}).get('subject_cn') == 'localhost', trusted
    assert '/must-not-follow' not in hits, hits
    secure.shutdown(); secure.server_close()
print('HTTPX runtime checks passed (metadata, no redirects, strict TLS, no protocol fallback)')
