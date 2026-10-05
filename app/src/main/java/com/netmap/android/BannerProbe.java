package com.netmap.android;

/** Passive greeting reads for FTP, SSH and Telnet. */
final class BannerProbe implements DeviceProbe {
    private final ProbeContext context;

    BannerProbe(ProbeContext context) {
        this.context = context;
    }

    @Override
    public boolean supports(int port, String type) {
        return port == 21 || port == 22 || port == 23;
    }

    @Override
    public void probe(String host, int port, String type) {
        String banner = context.read(host, port, null, 4096);
        String line = banner.split("\\r?\\n", 2)[0];
        if (!line.isEmpty()) context.evidence.add(host, "Banner tcp/" + port, "banner", line);
        else context.evidence.add(host, "Banner tcp/" + port, "probeStatus", "No banner received");
    }
}
