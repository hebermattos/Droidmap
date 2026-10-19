package com.netmap.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Offline Bluetooth SIG assigned-number names; loaded off the UI thread. */
final class BluetoothCatalog {
    private static volatile Map<String, String> names = Collections.emptyMap();
    static boolean loaded() { return !names.isEmpty(); }
    static void load(InputStream input) throws IOException {
        Map<String, String> parsed = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("#") || line.isEmpty()) continue;
                if (line.length() > 1024 || parsed.size() >= 10000) throw new IOException("Bluetooth catalog exceeds bounds");
                int tab = line.indexOf('\t');
                if (tab < 2 || tab == line.length() - 1 || !line.substring(0, tab).matches("[CU][0-9A-F]{8}"))
                    throw new IOException("Invalid Bluetooth catalog row");
                if (parsed.put(line.substring(0, tab), line.substring(tab + 1)) != null) throw new IOException("Duplicate Bluetooth identifier");
            }
        }
        if (parsed.isEmpty()) throw new IOException("Empty Bluetooth catalog");
        names = Collections.unmodifiableMap(parsed);
    }
    static String company(int id) { return names.getOrDefault(String.format(Locale.ROOT, "C%08X", id), ""); }
    static String uuid(String uuid) {
        if (uuid == null || !uuid.toLowerCase(Locale.ROOT).matches("[0-9a-f]{8}-0000-1000-8000-00805f9b34fb")) return "";
        return names.getOrDefault("U" + uuid.substring(0, 8).toUpperCase(Locale.ROOT), "");
    }
}
