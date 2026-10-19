package com.netmap.android;

import java.util.*;
import java.util.concurrent.atomic.*;

public final class BluetoothSettingsTests {
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    static final class Clock implements BluetoothDeadlines.Scheduler {
        final Map<Runnable,Long> queued = new LinkedHashMap<>();
        long now;
        public void post(Runnable task, long delay) { queued.put(task, now+delay); }
        public void remove(Runnable task) { queued.remove(task); }
        void advance(long millis) {
            now += millis;
            for (var item : new ArrayList<>(queued.entrySet()))
                if (item.getValue() <= now && queued.remove(item.getKey()) != null) item.getKey().run();
        }
    }
    public static void main(String[] args) {
        BluetoothSettings defaults = BluetoothSettings.defaults();
        check(defaults.mode.equals("Both") && defaults.discoverySeconds == 30 && defaults.sdpSeconds == 30
                && defaults.gattSeconds == 30 && defaults.readSeconds == 30, "Defaults use BLE + Classic and 30 seconds for every timeout");
        for (String mode : BluetoothSettings.MODES) for (int seconds : BluetoothSettings.SECONDS) {
            BluetoothSettings value = new BluetoothSettings(mode, seconds, seconds, seconds, seconds);
            check(BluetoothSettings.SECONDS[BluetoothSettings.index(value.readSeconds)] == seconds, "Option round trip");
        }
        try { new BluetoothSettings("BLE", -1, 0, 0, 0); throw new AssertionError("Negative timeout accepted"); }
        catch (IllegalArgumentException expected) { }
        Clock clock = new Clock(); BluetoothDeadlines deadlines = new BluetoothDeadlines(clock);
        AtomicInteger fired = new AtomicInteger(); AtomicBoolean active = new AtomicBoolean(true);
        deadlines.arm("discovery", 0, active::get, fired::incrementAndGet);
        check(clock.queued.isEmpty(), "No limit schedules no automatic stop");
        deadlines.arm("sdp", 5, active::get, fired::incrementAndGet);
        clock.advance(4999); check(fired.get() == 0, "SDP waits for its configured time");
        clock.advance(1); check(fired.get() == 1, "SDP deadline fires at the boundary");
        deadlines.arm("read", 10, active::get, fired::incrementAndGet);
        Runnable stale = clock.queued.keySet().iterator().next();
        deadlines.arm("read", 5, active::get, fired::incrementAndGet);
        stale.run(); check(fired.get() == 1, "Old read cannot end a later read");
        deadlines.cancel("read"); clock.advance(10000); stale.run();
        check(fired.get() == 1 && clock.queued.isEmpty(), "Read completion cancels its timer");
        deadlines.arm("gatt", 5, active::get, fired::incrementAndGet);
        active.set(false); clock.advance(5000); check(fired.get() == 1, "Old run or device is ignored");
        active.set(true);
        deadlines.arm("gatt", 5, active::get, fired::incrementAndGet);
        deadlines.arm("read", 10, active::get, fired::incrementAndGet);
        List<Runnable> stopped = new ArrayList<>(clock.queued.keySet());
        deadlines.clear(); stopped.forEach(Runnable::run); clock.advance(300000);
        check(fired.get() == 1 && clock.queued.isEmpty(), "Stop clears every deadline including already dispatched callbacks");
        deadlines.arm("gatt", 5, active::get, fired::incrementAndGet);
        deadlines.arm("gatt", 0, active::get, fired::incrementAndGet);
        clock.advance(5000); check(fired.get() == 1, "Disabling a deadline removes the old timer");
        System.out.println("PASS: Bluetooth timeout options, no-limit, boundaries, stale callbacks and cancellation");
    }
}
