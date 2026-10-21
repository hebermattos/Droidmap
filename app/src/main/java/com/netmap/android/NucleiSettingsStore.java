package com.netmap.android;

import android.content.Context;
import android.content.SharedPreferences;

final class NucleiSettingsStore {
    private final SharedPreferences preferences;
    NucleiSettingsStore(Context context) {
        preferences = context.getSharedPreferences("nuclei-options", Context.MODE_PRIVATE);
    }
    int load() {
        int mask = preferences.getInt("coverageGroups", NucleiTemplates.ALL);
        try { return NucleiTemplates.validate(mask); }
        catch (IllegalArgumentException error) { return NucleiTemplates.ALL; }
    }
    void save(int mask) { preferences.edit().putInt("coverageGroups", NucleiTemplates.validate(mask)).apply(); }
}
