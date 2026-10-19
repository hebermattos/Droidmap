package com.netmap.android;

/** Retry only a failed connection establishment, never authentication or later operations. */
final class BluetoothGattRetry {
    static final int MAX_ATTEMPTS = 2;
    static final long DELAY_MS = 2000;
    static boolean eligible(int attempts, int connectionStatus, boolean connected, boolean connectable) {
        return attempts == 1 && !connected && connectable
                && (connectionStatus == 8 || connectionStatus == 62 || connectionStatus == 133 || connectionStatus == 147);
    }
}
