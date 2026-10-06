package com.netmap.android;

import java.util.*;

/** Validated sourced observations, never a claim of factory identity or current reachability. */
final class MacAddresses {
    private MacAddresses() {}

    static String normalize(String value) {
        if (value == null || !value.matches("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}")) return "";
        String mac = value.toUpperCase(Locale.ROOT);
        int first = Integer.parseInt(mac.substring(0, 2), 16);
        if ((first & 1) != 0 || mac.equals("00:00:00:00:00:00")
                || mac.equals("02:00:00:00:00:00")) return "";
        return mac;
    }

    static String kind(String mac) {
        return (Integer.parseInt(mac.substring(0, 2), 16) & 2) != 0
                ? "Locally administered (may be randomized)" : "Universally administered";
    }

    static List<DeviceEvidence.Observation> observations(List<DeviceEvidence.Observation> info) {
        List<DeviceEvidence.Observation> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (DeviceEvidence.Observation item : info) {
            if (!item.field.equals("reportedMac") && !item.field.equals("neighborMac")
                    && !item.field.equals("macAddress")) continue;
            String mac = normalize(item.value);
            if (!mac.isEmpty() && seen.add(item.source + "/" + mac))
                result.add(new DeviceEvidence.Observation(item.source, item.field, mac));
        }
        return result;
    }
}
