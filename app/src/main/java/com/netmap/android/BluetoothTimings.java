package com.netmap.android;

import java.util.*;

/** Elapsed and remaining time use the same monotonic uptime clock as Handler deadlines. */
final class BluetoothTimings {
    record Snapshot(String key, int limitSeconds, long elapsedMs, long remainingMs, String outcome) {
        boolean running() { return outcome.equals("running"); }
        int percent() { return limitSeconds == 0 ? 0 : (int)Math.min(100, elapsedMs * 100 / (limitSeconds * 1000L)); }
    }
    private static final class Timer {
        final long started;
        final int seconds;
        long ended = -1;
        String outcome = "running";
        Timer(long now, int seconds) { started = now; this.seconds = seconds; }
    }
    private final Map<String, Timer> timers = new LinkedHashMap<>();
    void start(String key, int seconds, long now) { timers.put(key, new Timer(now, seconds)); }
    void finish(String key, String outcome, long now) {
        Timer timer = timers.get(key);
        if (timer != null && timer.ended < 0) { timer.ended = now; timer.outcome = outcome; }
    }
    void stop(long now) { for (String key : timers.keySet()) finish(key, "stopped", now); }
    List<Snapshot> snapshots(long now) {
        List<Snapshot> result = new ArrayList<>();
        for (var entry : timers.entrySet()) {
            Timer timer = entry.getValue();
            long elapsed = Math.max(0, (timer.ended < 0 ? now : timer.ended) - timer.started);
            result.add(new Snapshot(entry.getKey(), timer.seconds, elapsed,
                    timer.seconds == 0 ? -1 : Math.max(0, timer.seconds * 1000L - elapsed), timer.outcome));
        }
        return result;
    }
    static String label(String key) {
        return switch (key) {
            case "discovery" -> "Discovery"; case "sdp" -> "SDP response";
            case "gatt" -> "GATT attempt"; case "read" -> "Current read";
            case "retry" -> "Connection retry";
            default -> key;
        };
    }
    static String clock(long seconds) {
        seconds = Math.max(0, seconds);
        return String.format(Locale.ROOT, "%02d:%02d", seconds / 60, seconds % 60);
    }
    static String describe(Snapshot timer) {
        String elapsed = clock(timer.elapsedMs / 1000);
        String value;
        if (!timer.running()) value = (timer.outcome.equals("timed_out") ? "Timed out" : timer.outcome.equals("stopped") ? "Stopped" : "Finished") + " • " + elapsed + " elapsed";
        else if (timer.limitSeconds == 0) value = "No limit • " + elapsed + " elapsed";
        else value = clock((timer.remainingMs + 999) / 1000) + " left / " + clock(timer.limitSeconds)
                + (timer.remainingMs == 0 ? " • finishing…" : "");
        return label(timer.key) + ": " + value;
    }
}
