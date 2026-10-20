package com.netmap.android;

import java.io.*;
import java.nio.charset.StandardCharsets;

public final class MacVendorTests {
    private static void check(boolean value) { if (!value) throw new AssertionError(); }
    public static void main(String[] args) throws Exception {
        check(MacVendorCatalog.identify("D0:03:DF:A8:3D:7F", "public", false).status().equals("Registry unavailable"));
        check(MacVendorCatalog.identifyWifi("D0:03:DF:A8:3D:7F").status().equals("Registry unavailable"));
        try (InputStream input = new FileInputStream(args[0])) { MacVendorCatalog.load(input); }
        var samsung = MacVendorCatalog.identify("d0:03:df:a8:3d:7f", "public", false);
        check(samsung.vendor().contains("Samsung"));
        check(samsung.prefix().equals("D003DF"));
        check(samsung.status().equals("IEEE prefix match"));
        check(MacVendorCatalog.identifyWifi("d0:03:df:a8:3d:7f").vendor().contains("Samsung"));
        check(MacVendorCatalog.identifyWifi("D0:03:DF:A8:3D:7F").addressType().equals("Universally administered"));
        for (String local : new String[]{"D2:03:DF:A8:3D:7F", "02:9C:1F:F3:EA:26", "CE:24:04:6A:12:34"}) {
            check(MacVendorCatalog.identifyWifi(local).vendor().isEmpty());
            check(MacVendorCatalog.identifyWifi(local).status().equals("Unavailable for local address"));
        }
        for (String invalid : new String[]{"garbage", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:02:03:04:05:06"})
            check(MacVendorCatalog.identifyWifi(invalid).status().equals("Unavailable"));
        check(MacVendorCatalog.identify("D0:03:DF:A8:3D:7F", "unknown", false).status().startsWith("Candidate"));
        check(MacVendorCatalog.identify("D0:03:DF:A8:3D:7F", "unknown", true).addressType().equals("Public"));
        for (String mac : new String[]{"D0:03:DF:A8:3D:7F", "02:9C:1F:F3:EA:26", "43:35:7C:CD:14:CD", "80:00:00:00:00:01"}) {
            var random = MacVendorCatalog.identify(mac, "random", true);
            check(random.vendor().isEmpty()); // Even a real Samsung prefix is unusable when random.
            check(random.addressType().startsWith("Random"));
        }
        check(MacVendorCatalog.identify("43:35:7C:CD:14:CD", "random", false).addressType().contains("resolvable"));
        for (String invalid : new String[]{"", "garbage", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "02:00:00:00:00:00"})
            check(MacVendorCatalog.identify(invalid, "public", false).status().equals("Unavailable"));
        // Most-specific assignment wins. BLE addresses must not be rejected by Wi-Fi local/multicast rules.
        MacVendorCatalog.load(new ByteArrayInputStream(("010203\tLarge\n0102034\tMedium\n010203456\tSmall\n"
                + "000203\tWiFi large\n0002034\tWiFi medium\n000203456\tWiFi small\n020203\tLocal trap\n").getBytes(StandardCharsets.UTF_8)));
        check(MacVendorCatalog.identifyWifi("00:02:03:45:67:89").vendor().equals("WiFi small"));
        check(MacVendorCatalog.identifyWifi("00:02:03:4A:67:89").vendor().equals("WiFi medium"));
        check(MacVendorCatalog.identifyWifi("00:02:03:5A:67:89").vendor().equals("WiFi large"));
        check(MacVendorCatalog.identifyWifi("02:02:03:5A:67:89").vendor().isEmpty());
        check(MacVendorCatalog.identifyWifi("00:02:04:5A:67:89").status().equals("No registered prefix found"));
        check(MacVendorCatalog.identify("01:02:03:45:67:89", "unknown", false).vendor().equals("Small"));
        check(MacVendorCatalog.identify("01:02:03:4A:67:89", "public", false).vendor().equals("Medium"));
        check(MacVendorCatalog.identify("01:02:03:5A:67:89", "public", false).vendor().equals("Large"));
        check(MacVendorCatalog.identify("04:02:03:5A:67:89", "public", false).status().equals("No registered prefix found"));
        for (String invalid : new String[]{"", "no-tab", "ABC\tShort", "ABCDEF\t", "ABCDEF\tA\nABCDEF\tB", "ABCDEF\tA\tB"}) {
            try {
                MacVendorCatalog.load(new ByteArrayInputStream(invalid.getBytes(StandardCharsets.UTF_8)));
                throw new AssertionError("Malformed registry accepted");
            } catch (IOException expected) { }
            check(MacVendorCatalog.identify("01:02:03:45:67:89", "public", false).vendor().equals("Small"));
        }
        System.out.println("MAC vendor tests passed (IEEE catalog, address privacy, prefix precedence, atomic validation)");
    }
}
