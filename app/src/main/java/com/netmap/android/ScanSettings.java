package com.netmap.android;

/** Immutable scan options; shared by the settings editor and scan startup. */
final class ScanSettings {
    static final int DEFAULT_TIMEOUT_MS = 200;
    final String ports;
    final int timeoutMs;
    final ScanPlan.Mode mode;
    final boolean adaptive;

    ScanSettings(String ports, int timeoutMs, ScanPlan.Mode mode, boolean adaptive) {
        ScanPlan.parsePorts(ports);
        if (timeoutMs < 100 || timeoutMs > 3000) {
            throw new IllegalArgumentException("Timeout must be 100–3000 ms.");
        }
        this.ports = ports;
        this.timeoutMs = timeoutMs;
        this.mode = java.util.Objects.requireNonNull(mode);
        this.adaptive = adaptive;
    }

    ScanSettings completeDefaults() {
        return new ScanSettings(
                ScanPlan.COMPLETE_PORTS, timeoutMs, ScanPlan.Mode.COMPLETE, adaptive);
    }

    String summary() {
        return (mode == ScanPlan.Mode.FAST ? "Fast" : "Complete")
                + " • "
                + ScanPlan.parsePorts(ports).size()
                + " ports • "
                + timeoutMs
                + " ms"
                + (adaptive ? " • Adaptive" : "");
    }
}
