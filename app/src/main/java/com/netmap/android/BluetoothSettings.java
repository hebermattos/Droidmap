package com.netmap.android;

/** Immutable Bluetooth options. Zero seconds explicitly disables an application deadline. */
final class BluetoothSettings {
    static final String[] MODES = {"BLE", "Classic", "Both"};
    static final int[] SECONDS = {0, 5, 10, 15, 30, 60, 120, 300};
    static final String[] LABELS = {"No limit", "5 seconds", "10 seconds", "15 seconds", "30 seconds", "60 seconds", "120 seconds", "300 seconds"};
    final String mode;
    final int discoverySeconds, sdpSeconds, gattSeconds, readSeconds;
    BluetoothSettings(String mode, int discovery, int sdp, int gatt, int read) {
        if (!java.util.Arrays.asList(MODES).contains(mode)) throw new IllegalArgumentException("Invalid Bluetooth mode");
        this.mode = mode;
        discoverySeconds = validate(discovery); sdpSeconds = validate(sdp);
        gattSeconds = validate(gatt); readSeconds = validate(read);
    }
    static BluetoothSettings defaults() { return new BluetoothSettings("Both", 30, 30, 30, 30); }
    static int validate(int seconds) {
        for (int value : SECONDS) if (value == seconds) return seconds;
        throw new IllegalArgumentException("Invalid Bluetooth timeout");
    }
    static int index(int seconds) {
        for (int i=0; i<SECONDS.length; i++) if (SECONDS[i] == seconds) return i;
        return 0;
    }
}
