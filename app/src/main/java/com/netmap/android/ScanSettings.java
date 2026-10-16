package com.netmap.android;

/** Immutable scan options; shared by the settings editor and scan startup. */
final class ScanSettings {
    static final int DEFAULT_TIMEOUT_MS = 200;
    final String ports;
    final int timeoutMs;
    final ScanPlan.Mode mode;
    final boolean adaptive;
    final boolean nmap;

    ScanSettings(String ports, int timeoutMs, ScanPlan.Mode mode, boolean adaptive) { this(ports,timeoutMs,mode,adaptive,true); }

    ScanSettings(String ports, int timeoutMs, ScanPlan.Mode mode, boolean adaptive, boolean nmap) {
        ScanPlan.parsePorts(ports);
        if (timeoutMs < 100 || timeoutMs > 3000) {
            throw new IllegalArgumentException("Timeout must be 100–3000 ms.");
        }
        this.ports = ports;
        this.timeoutMs = timeoutMs;
        this.mode = java.util.Objects.requireNonNull(mode);
        this.adaptive = adaptive;
        this.nmap = nmap;
    }

    ScanSettings completeDefaults() {
        return new ScanSettings(
                ScanPlan.COMPLETE_PORTS, timeoutMs, ScanPlan.Mode.COMPLETE, adaptive, nmap);
    }

    String summary() {
        return (mode == ScanPlan.Mode.FAST ? "Fast" : "Complete")
                + " • "
                + ScanPlan.parsePorts(ports).size()
                + " ports • "
                + timeoutMs
                + " ms"
                + (adaptive ? " • Adaptive" : "")
                + (nmap ? " • Nmap On" : " • Nmap Off");
    }
}
