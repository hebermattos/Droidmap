package com.netmap.android;

import android.content.Context;
import android.content.SharedPreferences;

/** Preferences are independent of network scan settings and captured once per Bluetooth run. */
final class BluetoothSettingsStore {
    private final SharedPreferences preferences;
    BluetoothSettingsStore(Context context) { preferences = context.getSharedPreferences("bluetooth-options", Context.MODE_PRIVATE); }
    BluetoothSettings load() {
        try {
            return new BluetoothSettings(preferences.getString("mode", "BLE"),
                    preferences.getInt("discovery", 0), preferences.getInt("sdp", 0),
                    preferences.getInt("gatt", 0), preferences.getInt("read", 0));
        } catch (IllegalArgumentException | ClassCastException invalid) { return BluetoothSettings.defaults(); }
    }
    void save(BluetoothSettings settings) {
        preferences.edit().putString("mode", settings.mode).putInt("discovery", settings.discoverySeconds)
                .putInt("sdp", settings.sdpSeconds).putInt("gatt", settings.gattSeconds)
                .putInt("read", settings.readSeconds).apply();
    }
}
