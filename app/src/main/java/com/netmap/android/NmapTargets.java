package com.netmap.android;

import java.util.*;

/** All validated planned and discovered targets, without a mode-dependent Nmap host budget. */
final class NmapTargets {
    static List<String> collect(ScanPlan plan, DeviceEvidence evidence) {
        LinkedHashSet<String> targets = new LinkedHashSet<>();
        for (String host : plan.hosts) targets.add(IpAddresses.canonical(host));
        targets.addAll(evidence.snapshot().keySet());
        return new ArrayList<>(targets);
    }
}
