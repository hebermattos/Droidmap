package com.netmap.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** IEEE registration owners, not a database of device models or physical identities. */
final class MacVendorCatalog {
    private static volatile Map<String, String> vendors = Collections.emptyMap();
    record Identification(String addressType, String status, String vendor, String prefix, String note) {
        String summary() {
            return "Address type: " + addressType + "\nMAC manufacturer: "
                    + (vendor.isEmpty() ? status : vendor + " [" + status + "]") + "\n" + note;
        }
    }
    static boolean loaded() { return !vendors.isEmpty(); }
    static void load(InputStream input) throws IOException {
        Map<String, String> parsed = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty() || line.startsWith("#")) continue;
                int tab = line.indexOf('\t');
                if (line.length() > 1024 || parsed.size() >= 100000 || tab < 0
                        || !line.substring(0, tab).matches("(?:[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9})")
                        || tab == line.length() - 1 || line.substring(tab + 1).chars().anyMatch(Character::isISOControl))
                    throw new IOException("Invalid or oversized MAC registry");
                if (parsed.put(line.substring(0, tab), line.substring(tab + 1)) != null)
                    throw new IOException("Duplicate MAC prefix");
            }
        }
        if (parsed.isEmpty()) throw new IOException("Empty MAC registry");
        vendors = Collections.unmodifiableMap(parsed);
    }

    static Identification identifyWifi(String address) {
        String mac = MacAddresses.normalize(address);
        if (mac.isEmpty()) return new Identification("Unknown", "Unavailable", "", "", "No usable Wi-Fi MAC address was observed.");
        if ((Integer.parseInt(mac.substring(0, 2), 16) & 2) != 0)
            return new Identification(MacAddresses.kind(mac), "Unavailable for local address", "", "",
                    "Locally administered Wi-Fi addresses may be randomized or manually assigned; their prefix cannot reliably identify a manufacturer.");
        Identification match = identify(mac, "public", false);
        return new Identification(MacAddresses.kind(mac), match.status(), match.vendor(), match.prefix(), match.note());
    }

    static Identification identify(String address, String type, boolean classicObserved) {
        String normalized = address == null ? "" : address.toUpperCase(Locale.ROOT);
        if (!normalized.matches("(?:[0-9A-F]{2}:){5}[0-9A-F]{2}")
                || normalized.equals("00:00:00:00:00:00") || normalized.equals("FF:FF:FF:FF:FF:FF")
                || normalized.equals("02:00:00:00:00:00"))
            return new Identification("Unknown", "Unavailable", "", "", "No usable Bluetooth address.");
        // BLE random addresses do not use Ethernet's individual/local bit rules.
        if ("random".equals(type)) {
            int bits = Integer.parseInt(normalized.substring(0, 2), 16) >>> 6;
            String label = switch (bits) {
                case 0 -> "Random private (non-resolvable)";
                case 1 -> "Random private (resolvable)";
                case 3 -> "Random static";
                default -> "Random (reserved pattern)";
            };
            return new Identification(label, "Unavailable for random address", "", "",
                    "Random Bluetooth addresses have no reliable IEEE manufacturer prefix.");
        }
        boolean publicAddress = "public".equals(type) || classicObserved;
        String label = publicAddress ? "Public" : "Unknown";
        if (!loaded()) return new Identification(label, "Registry unavailable", "", "", "Offline IEEE registry is not loaded.");
        String hex = normalized.replace(":", "");
        Map<String,String> snapshot = vendors;
        for (int length : new int[]{9, 7, 6}) {
            String prefix = hex.substring(0, length), vendor = snapshot.get(prefix);
            if (vendor != null) return new Identification(label, publicAddress ? "IEEE prefix match" : "Candidate; address type unknown",
                    vendor, prefix, publicAddress
                    ? "IEEE registration owner; may identify a component supplier. Model and physical identity are unverified."
                    : "A random address may match by chance. Manufacturer is unverified; address bits alone do not establish its type.");
        }
        return new Identification(label, "No registered prefix found", "", "", "No match in the bundled IEEE registry; device identity remains unknown.");
    }
}
