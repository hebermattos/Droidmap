package com.netmap.android;

import java.util.*;

/** Every found host with verified-open TCP ports; no mode-dependent host budget. */
final class NmapTargets {
    static Map<String, LinkedHashSet<Integer>> collect(Collection<TcpScanner.Result> checks,
            DeviceEvidence evidence) {
        Map<String, LinkedHashSet<Integer>> targets = new LinkedHashMap<>();
        for (TcpScanner.Result check : checks) {
            if (check.state != TcpScanner.State.OPEN || check.port < 1 || check.port > 65535
                    || !evidence.isAllowed(check.host)) continue;
            String host = IpAddresses.canonical(check.host);
            targets.computeIfAbsent(host, key -> new LinkedHashSet<>()).add(check.port);
        }
        return targets;
    }
}
