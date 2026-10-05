package com.netmap.android;

import java.util.Map;

/** Plain HTTP only when explicitly announced or on an existing supported HTTP port. */
final class HttpProbe implements DeviceProbe {
    private final ProbeContext context;

    HttpProbe(ProbeContext context) {
        this.context = context;
    }

    static boolean matches(int port, String type) {
        return type.startsWith("_http._tcp")
                || type.isEmpty() && (port == 80 || port == 8000 || port == 8080 || port == 8888);
    }

    @Override
    public boolean supports(int port, String type) {
        return matches(port, type);
    }

    @Override
    public void probe(String host, int port, String type) {
        String response =
                context.read(
                        host,
                        port,
                        "GET / HTTP/1.0\r\nHost: "
                                + host
                                + ":"
                                + port
                                + "\r\nUser-Agent: Netmap-Lite/0.4\r\nConnection: close\r\n\r\n",
                        16384);
        if (response.startsWith("HTTP/")) {
            Map<String, String> h = DeviceEvidence.headers(response);
            context.evidence.add(host, "HTTP tcp/" + port, "server", h.get("server"));
            context.evidence.add(
                    host, "HTTP tcp/" + port, "httpTitle", DeviceEvidence.title(response));
        } else context.evidence.add(host, "HTTP tcp/" + port, "probeStatus", "No valid HTTP reply");
    }
}
