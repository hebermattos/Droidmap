#!/usr/bin/env python3
"""Apply Droidmap's strict TLS dialer to the pinned HTTPX source (fail on drift)."""
from pathlib import Path
import sys
p = Path(sys.argv[1]) / 'common/httpx/httpx.go'
s = p.read_text()
start = s.index('func (h *HTTPX) buildTLSDialer(')
end = s.index('\nfunc resolveImpersonateStrategy(', start)
# Always verify certificate trust and endpoint identity. Use the existing TCP dialer
# but never its permissive TLS defaults or alternate impersonation/ZTLS paths.
s = s[:start] + '''func (h *HTTPX) buildTLSDialer(options *Options, _ *tls.Config) func(context.Context, string, string) (net.Conn, error) {
    return func(ctx context.Context, network, addr string) (net.Conn, error) {
        host, _, err := net.SplitHostPort(addr)
        if err != nil { return nil, err }
        conn, err := h.Dialer.Dial(ctx, network, addr)
        if err != nil { return nil, err }
        secured := tls.Client(conn, &tls.Config{
            ServerName: host, MinVersion: tls.VersionTLS12,
            NextProtos: explicitALPN(options.Protocol),
        })
        if err := secured.HandshakeContext(ctx); err != nil {
            conn.Close()
            return nil, err
        }
        return secured, nil
    }
}
''' + s[end:]
# Also keep the standard transport configurations strict.
assert s.count('InsecureSkipVerify: true,') == 2
s = s.replace('InsecureSkipVerify: true,', 'InsecureSkipVerify: false,')
p.write_text(s)
