package com.netmap.android;

import java.util.Map;

/** Rtsp metadata; no authentication or device changes. */
final class RtspProbe implements DeviceProbe {
    private final ProbeContext context;

    RtspProbe(ProbeContext context) {
        this.context = context;
    }

    static boolean matches(int port, String type) {
        return type.startsWith("_rtsp._tcp") || type.isEmpty() && port == 554;
    }

    @Override
    public boolean supports(int port, String type) {
        return matches(port, type);
    }

    @Override
    public void probe(String host, int port, String type) {
        String reply =
                context.read(
                        host,
                        port,
                        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Droidmap\r\n\r\n",
                        8192);
        Map<String, String> fields = DeviceEvidence.headers(reply);
        if (!reply.matches("(?s)RTSP/1\\.0 [1-5][0-9]{2}\\b.*")
                || !"1".equals(fields.get("cseq"))) {
            context.evidence.add(host, "RTSP tcp/" + port, "probeStatus", "No valid RTSP reply");
            return;
        }
        context.evidence.add(host, "RTSP tcp/" + port, "serviceType", "_rtsp._tcp.");
        context.evidence.add(host, "RTSP tcp/" + port, "server", fields.get("server"));
        context.evidence.add(host, "RTSP tcp/" + port, "supportedMethods", fields.get("public"));
        context.evidence.add(
                host, "RTSP tcp/" + port, "responseStatus", reply.split("\r?\n", 2)[0]);
    }
}
