package com.netmap.android;

import java.util.*;
import java.util.function.BooleanSupplier;

/** Main-thread deadline ownership; cancelled/replaced callbacks cannot affect later operations. */
final class BluetoothDeadlines {
    interface Scheduler {
        void post(Runnable task, long delayMs);
        void remove(Runnable task);
    }
    private final Scheduler scheduler;
    private final Map<String, Runnable> pending = new HashMap<>();
    BluetoothDeadlines(Scheduler scheduler) { this.scheduler = scheduler; }
    void cancel(String key) {
        Runnable old = pending.remove(key);
        if (old != null) scheduler.remove(old);
    }
    void clear() {
        for (String key : new ArrayList<>(pending.keySet())) cancel(key);
    }
    void arm(String key, int seconds, BooleanSupplier active, Runnable action) {
        BluetoothSettings.validate(seconds);
        cancel(key);
        if (seconds == 0) return;
        Runnable task = new Runnable() {
            @Override public void run() {
                if (pending.get(key) != this) return;
                pending.remove(key);
                if (active.getAsBoolean()) action.run();
            }
        };
        pending.put(key, task);
        scheduler.post(task, seconds * 1000L);
    }
}
