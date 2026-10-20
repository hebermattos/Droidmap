package com.netmap.android;

/** Immutable scan options; shared by the settings editor and scan startup. */
final class ScanSettings {
    enum Preset {
        QUICK("Quick", ScanPlan.FAST_PORTS, ScanPlan.Mode.FAST,
                "Common TCP ports and shorter discovery. Recommended for everyday use."),
        DETAILED("Detailed", ScanPlan.COMPLETE_PORTS, ScanPlan.Mode.COMPLETE,
                "More TCP ports, one retry and longer device discovery."),
        ALL("All ports", ScanPlan.ALL_PORTS, ScanPlan.Mode.COMPLETE,
                "Checks TCP ports 1–65535. Can take hours across a network."),
        CUSTOM("Custom", null, null,
                "Choose TCP ports or ranges, such as 22,80,443,8000-8010.");

        final String label, ports, description;
        final ScanPlan.Mode mode;
        Preset(String label, String ports, ScanPlan.Mode mode, String description) {
            this.label=label; this.ports=ports; this.mode=mode; this.description=description;
        }
        String selection(String customPorts) { return this==CUSTOM?customPorts.trim():ports; }
        ScanPlan.Mode depth(boolean thorough) {
            return this==CUSTOM?(thorough?ScanPlan.Mode.COMPLETE:ScanPlan.Mode.FAST):mode;
        }
    }

    static final int DEFAULT_TIMEOUT_MS = 200;
    final String ports;
    final int timeoutMs;
    final ScanPlan.Mode mode;
    final boolean adaptive;
    final boolean nmap;
    final String nmapArgs;
    final int nmapVersionIntensity;

    ScanSettings(String ports, int timeoutMs, ScanPlan.Mode mode, boolean adaptive) { this(ports,timeoutMs,mode,adaptive,true,""); }

    ScanSettings(String ports, int timeoutMs, ScanPlan.Mode mode, boolean adaptive, boolean nmap) { this(ports,timeoutMs,mode,adaptive,nmap,""); }

    ScanSettings(String ports, int timeoutMs, ScanPlan.Mode mode, boolean adaptive, boolean nmap, String nmapArgs) {
        this(ports, timeoutMs, mode, adaptive, nmap, nmapArgs, NmapCommands.DEFAULT_VERSION_INTENSITY);
    }

    ScanSettings(String ports, int timeoutMs, ScanPlan.Mode mode, boolean adaptive, boolean nmap,
            String nmapArgs, int nmapVersionIntensity) {
        ScanPlan.parsePorts(ports);
        if (timeoutMs < 100 || timeoutMs > 3000) {
            throw new IllegalArgumentException("Timeout must be 100–3000 ms.");
        }
        this.nmapVersionIntensity = NmapCommands.bounded(nmapVersionIntensity, 0, 9, "Nmap version intensity");
        this.ports = ports;
        this.timeoutMs = timeoutMs;
        this.mode = java.util.Objects.requireNonNull(mode);
        this.adaptive = adaptive;
        this.nmap = nmap;
        this.nmapArgs = nmapArgs == null ? "" : nmapArgs.trim();
    }

    ScanSettings completeDefaults() {
        return new ScanSettings(
                ScanPlan.COMPLETE_PORTS, timeoutMs, ScanPlan.Mode.COMPLETE, adaptive, nmap, nmapArgs, nmapVersionIntensity);
    }

    Preset preset() {
        java.util.List<Integer> selected=ScanPlan.parsePorts(ports);
        for(Preset preset:Preset.values())
            if(preset!=Preset.CUSTOM && mode==preset.mode
                    && selected.equals(ScanPlan.parsePorts(preset.ports))) return preset;
        return Preset.CUSTOM;
    }

    String summary() {
        return preset().label + " • " + ScanPlan.parsePorts(ports).size() + " TCP ports";
    }
}
