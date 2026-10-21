package com.netmap.android;

import java.util.List;

/** The nearest active deadline drives the compact countdown; detailed phase timers remain available. */
final class BluetoothTimingSummary {
    private BluetoothTimingSummary() {}
    static BluetoothTimings.Snapshot current(List<BluetoothTimings.Snapshot> timers) {
        BluetoothTimings.Snapshot current=null;
        for(BluetoothTimings.Snapshot timer:timers) {
            if(!timer.running())continue;
            if(current==null || timer.limitSeconds()>0 && (current.limitSeconds()==0 || timer.remainingMs()<current.remainingMs()))
                current=timer;
        }
        return current;
    }
}
