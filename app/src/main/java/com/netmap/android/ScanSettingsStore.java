package com.netmap.android;

import android.content.SharedPreferences;

/** Keeps the existing preference keys and one-time timeout migration. */
final class ScanSettingsStore {
    private final SharedPreferences preferences;

    ScanSettingsStore(SharedPreferences preferences) {
        this.preferences = preferences;
    }

    ScanSettings load() {
        int timeout = preferences.getInt("timeout", ScanSettings.DEFAULT_TIMEOUT_MS);
        if (!preferences.getBoolean("timeoutDefault200", false)) {
            if (timeout == 500) timeout = ScanSettings.DEFAULT_TIMEOUT_MS;
            preferences
                    .edit()
                    .putInt("timeout", timeout)
                    .putBoolean("timeoutDefault200", true)
                    .apply();
        }
        return new ScanSettings(
                preferences.getString("ports", ScanPlan.FAST_PORTS),
                timeout,
                preferences.getBoolean("complete", false)
                        ? ScanPlan.Mode.COMPLETE
                        : ScanPlan.Mode.FAST,
                preferences.getBoolean("adaptive", true),
                preferences.getBoolean("nmap", true));
    }

    void save(ScanSettings settings) {
        preferences
                .edit()
                .putString("ports", settings.ports)
                .putInt("timeout", settings.timeoutMs)
                .putBoolean("complete", settings.mode == ScanPlan.Mode.COMPLETE)
                .putBoolean("adaptive", settings.adaptive)
                .putBoolean("nmap", settings.nmap)
                .apply();
    }
}
