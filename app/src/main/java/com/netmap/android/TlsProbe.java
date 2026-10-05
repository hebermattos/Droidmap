package com.netmap.android;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** Tls metadata; no authentication or device changes. */
final class TlsProbe implements DeviceProbe {
    private final ProbeContext context;

    TlsProbe(ProbeContext context) {
        this.context = context;
    }

    static boolean matches(int port, String type) {
        return type.startsWith("_https._tcp")
                || type.startsWith("_ipps._tcp")
                || type.isEmpty() && (port == 443 || port == 8443 || port == 5986);
    }

    @Override
    public boolean supports(int port, String type) {
        return matches(port, type);
    }

    @Override
    public void probe(String host, int port, String type) {
        if (context.stopped()) return;
        String source = "TLS tcp/" + port;
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
            context.track(socket);
            try {
                if (context.stopped()) return;
                SSLParameters parameters = socket.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(parameters);
                socket.connect(new InetSocketAddress(host, port), context.remainingTimeout(500));
                socket.setSoTimeout(
                        context.remainingTimeout(
                                context.plan.mode == ScanPlan.Mode.COMPLETE ? 1800 : 900));
                socket.startHandshake();
                if (context.stopped()) return;
                SSLSession session = socket.getSession();
                context.evidence.add(
                        host, source, "tlsValidation", "Validated trust chain and IP identity");
                context.evidence.add(host, source, "tlsVersion", session.getProtocol());
                context.evidence.add(host, source, "cipherSuite", session.getCipherSuite());
                X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];
                context.evidence.add(
                        host,
                        source,
                        "certificateSubject",
                        cert.getSubjectX500Principal().getName());
                context.evidence.add(
                        host, source, "certificateIssuer", cert.getIssuerX500Principal().getName());
                context.evidence.add(
                        host,
                        source,
                        "certificateExpires",
                        cert.getNotAfter().toInstant().toString());
                if (type.startsWith("_ipps")) return; // No plaintext or print operation.
                socket.getOutputStream()
                        .write(
                                ("GET / HTTP/1.0\r\nHost: "
                                                + host
                                                + ":"
                                                + port
                                                + "\r\nConnection: close\r\n\r\n")
                                        .getBytes(StandardCharsets.US_ASCII));
                byte[] raw = context.receive(socket, 16384);
                String reply = new String(raw, StandardCharsets.UTF_8);
                if (reply.startsWith("HTTP/")) {
                    context.evidence.add(
                            host,
                            "HTTPS tcp/" + port,
                            "server",
                            DeviceEvidence.headers(reply).get("server"));
                    context.evidence.add(
                            host,
                            "HTTPS tcp/" + port,
                            "httpTitle",
                            DeviceEvidence.title(
                                    new String(
                                            HttpReply.body(raw, "text/html"),
                                            StandardCharsets.UTF_8)));
                }
            } finally {
                context.untrack(socket);
            }
        } catch (SSLException e) {
            if (!context.stopped())
                context.evidence.add(
                        host,
                        source,
                        "probeStatus",
                        "TLS validation or handshake failed; certificate data unavailable");
        } catch (IOException | SecurityException e) {
            if (!context.stopped())
                context.evidence.add(
                        host,
                        source,
                        "probeStatus",
                        "TLS connection failed: " + e.getClass().getSimpleName());
        }
    }
}
