package com.netmap.android;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Ipp metadata; no authentication or device changes. */
final class IppProbe implements DeviceProbe {
    private final ProbeContext context;

    IppProbe(ProbeContext context) {
        this.context = context;
    }

    static boolean matches(int port, String type) {
        return type.startsWith("_ipp._tcp") || type.isEmpty() && port == 631;
    }

    @Override
    public boolean supports(int port, String type) {
        return matches(port, type);
    }

    @Override
    public void probe(String host, int port, String type) {
        if (context.stopped()) return;
        String resource =
                Ipp.resource(
                        DeviceEvidence.first(
                                context.evidence.observations(host), "printerResource"));
        if (resource == null) return;
        try {
            byte[] body = Ipp.request("ipp://" + host + ":" + port + resource);
            ByteArrayOutputStream request = new ByteArrayOutputStream();
            request.write(
                    ("POST "
                                    + resource
                                    + " HTTP/1.1\r\nHost: "
                                    + host
                                    + ":"
                                    + port
                                    + "\r\nContent-Type: application/ipp\r\nContent-Length: "
                                    + body.length
                                    + "\r\nConnection: close\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
            request.write(body);
            byte[] response = context.readBytes(host, port, request.toByteArray(), 65536);
            Map<String, String> fields = Ipp.parse(HttpReply.body(response, "application/ipp"));
            if (!fields.isEmpty())
                context.evidence.add(
                        host, "IPP Get-Printer-Attributes", "serviceType", "_ipp._tcp.");
            fields.forEach(
                    (field, value) ->
                            context.evidence.add(host, "IPP Get-Printer-Attributes", field, value));
        } catch (IOException ignored) {
        }
    }
}
