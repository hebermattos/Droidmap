package com.netmap.android;

import java.util.Map;

/** Smb metadata; no authentication or device changes. */
final class SmbProbe implements DeviceProbe {
    private final ProbeContext context;

    SmbProbe(ProbeContext context) {
        this.context = context;
    }

    static boolean matches(int port, String type) {
        return type.startsWith("_smb._tcp") || type.isEmpty() && port == 445;
    }

    @Override
    public boolean supports(int port, String type) {
        return matches(port, type);
    }

    @Override
    public void probe(String host, int port, String type) {
        Map<String, String> fields = Smb.parse(context.readBytes(host, port, Smb.request(), 65536));
        if (fields.isEmpty())
            context.evidence.add(
                    host, "SMB tcp/" + port, "probeStatus", "No valid SMB2 negotiation reply");
        else
            fields.forEach(
                    (field, value) -> context.evidence.add(host, "SMB tcp/" + port, field, value));
    }
}
