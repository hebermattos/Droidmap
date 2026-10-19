package com.netmap.android;

import java.util.*;

/** One active device, bounded unique pending addresses, and explicit cancellation. */
final class BluetoothInspectionQueue {
    record Candidate(String address, boolean observed, boolean ble, boolean connectable, int rssi) {}
    private final ArrayDeque<String> pending;
    private String active;
    private int completed;
    private final int total;
    BluetoothInspectionQueue(Collection<String> addresses) {
        LinkedHashSet<String> unique = new LinkedHashSet<>(addresses);
        if (unique.size() > 512) throw new IllegalArgumentException("Too many inspection targets");
        pending = new ArrayDeque<>(unique); total = pending.size();
    }
    static List<String> eligible(Collection<Candidate> candidates) {
        return candidates.stream().filter(c -> c.observed && c.ble && c.connectable)
                .sorted(Comparator.comparingInt(Candidate::rssi).reversed().thenComparing(Candidate::address))
                .map(Candidate::address).distinct().limit(512).collect(java.util.stream.Collectors.toList());
    }
    String next() {
        if (active != null) throw new IllegalStateException("Finish the active device first");
        active = pending.poll(); return active;
    }
    void complete() { if (active != null) { completed++; active = null; } }
    List<String> cancel() {
        List<String> cancelled = new ArrayList<>();
        if (active != null) cancelled.add(active);
        cancelled.addAll(pending); pending.clear(); active = null; return cancelled;
    }
    int completed() { return completed; }
    int total() { return total; }
}
