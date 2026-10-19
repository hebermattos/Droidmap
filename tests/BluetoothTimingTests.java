package com.netmap.android;

public final class BluetoothTimingTests {
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static BluetoothTimings.Snapshot timer(BluetoothTimings timers, String key, long now) {
        return timers.snapshots(now).stream().filter(t -> t.key().equals(key)).findFirst().orElseThrow();
    }
    public static void main(String[] args) {
        BluetoothTimings timings = new BluetoothTimings();
        timings.start("discovery", 30, 1000);
        check(timer(timings,"discovery",1000).remainingMs() == 30000, "Full configured duration at start");
        var active = timer(timings,"discovery",2500);
        check(active.elapsedMs() == 1500 && active.remainingMs() == 28500, "Elapsed and remaining share a monotonic clock");
        check(BluetoothTimings.describe(active).equals("Discovery: 00:29 left / 00:30"), "Remaining seconds round up");
        check(timer(timings,"discovery",16000).percent() == 50, "Half duration fills half progress bar");
        check(timer(timings,"discovery",999999).percent() == 100 && timer(timings,"discovery",999999).remainingMs() == 0,
                "Delayed handler dispatch never yields negative remaining time or excessive progress");
        timings.finish("discovery", "timed_out", 31000);
        timings.stop(50000);
        var ended = timer(timings,"discovery",999999);
        check(ended.elapsedMs() == 30000 && ended.outcome().equals("timed_out"), "Timeout freezes elapsed and Stop preserves the outcome");
        check(BluetoothTimings.describe(ended).contains("Timed out"), "Finished countdown displays the outcome");
        timings.start("gatt", 30, 40000); timings.start("read", 10, 45000);
        timings.finish("read", "finished", 46000);
        check(timer(timings,"read",60000).elapsedMs() == 1000 && timer(timings,"gatt",60000).remainingMs() == 10000,
                "Read completion freezes its timer while GATT continues");
        timings.start("read", 10, 47000);
        check(timer(timings,"read",48000).remainingMs() == 9000 && timer(timings,"gatt",48000).elapsedMs() == 8000,
                "Next read resets only the read timer");
        timings.start("sdp",0,50000);
        check(timer(timings,"sdp",55000).remainingMs() == -1 && BluetoothTimings.describe(timer(timings,"sdp",55000)).contains("No limit • 00:05 elapsed"),
                "Unlimited operations show elapsed time without a fake countdown");
        timings.stop(60000);
        check(timer(timings,"gatt",999999).elapsedMs() == 20000 && timer(timings,"sdp",999999).outcome().equals("stopped"),
                "Stop freezes all active timers");
        timings.start("retry",2,61000);
        check(BluetoothTimings.describe(timer(timings,"retry",61500)).equals("Connection retry: 00:02 left / 00:02"), "Retry delay is visible");
        check(BluetoothTimings.clock(300).equals("05:00"), "Long timeout formatting");
        check(new BluetoothTimings().snapshots(0).isEmpty(), "New device starts with no previous device timers");
        System.out.println("PASS: Bluetooth countdowns, elapsed time, per-read reset, retry, unlimited and frozen outcomes");
    }
}
