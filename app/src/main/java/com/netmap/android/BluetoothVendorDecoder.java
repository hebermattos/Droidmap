package com.netmap.android;

import java.util.*;

/** Passive interpretation only: every field has an evidence label and undecoded bytes are retained. */
final class BluetoothVendorDecoder {
    static final String CDP_SOURCE = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cdp/77b446d0-8cea-4821-ad21-fabdf4d9a569";
    static final String SWIFT_SOURCE = "https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/bluetooth-swift-pair";
    static final String JIELI_SOURCE = "https://doc.zh-jieli.com/SDKWiki/master/Jieli-Tech/fw-AC79_AIoT_SDK/4-bluetooth/4.4-bt-extensions.html";
    record Field(String label, String value, String evidence) {}
    record Result(String protocol, String confidence, List<Field> fields, String unknownHex, String note, String source) {}

    static Result decode(int company, String hex, String observedAddress) {
        byte[] data = bytes(hex);
        List<Field> fields = new ArrayList<>();
        fields.add(new Field("Payload size", data.length + " bytes", "observed"));
        if (company == 6 && data.length >= 27 && data[0] == 1 && (data[2] & 0xe0) == 0x20 && (data[2] & 31) <= 1) {
            int version = (data[1] & 255) >>> 5;
            if (version > 1) return opaque("Microsoft vendor advertisement", data, fields, "Unsupported CDP header version; no device type inferred.", CDP_SOURCE);
            String evidence = version == 1 ? "documented" : "inferred";
            fields.add(new Field("Scenario", "Bluetooth (1)", "documented"));
            fields.add(new Field("Device header version", String.valueOf(version), "observed"));
            fields.add(new Field("Advertised device kind", deviceKind(data[1] & 31), evidence));
            fields.add(new Field("Advertised Nearby Share scope", (data[2] & 31) == 1 ? "Everyone" : "Own devices", evidence));
            fields.add(new Field("Address-as-device-ID flag", String.valueOf((data[3] & 0x20) != 0), evidence));
            fields.add(new Field("Flags/status byte", String.format(Locale.ROOT, "0x%02X", data[3] & 255), "observed"));
            fields.add(new Field("Extended status bits", String.format(Locale.ROOT, "0x%X", data[3] & 15), evidence));
            return new Result(version == 1 ? "Microsoft CDP" : "Microsoft CDP-like", evidence, fields,
                    BluetoothAdvertisement.hex(Arrays.copyOfRange(data, 4, data.length)),
                    "Declared protocol metadata, not verified hardware or OS. " + (version == 0 ? "Version 0 is outside the cited version-1 layout; mapped fields are inferred. " : "")
                            + "Remaining bytes are opaque; they cannot reveal a hostname, account or stable physical identity.", CDP_SOURCE);
        }
        if (company == 6 && data.length >= 3 && data[0] == 3 && (data[2] & 255) == 128 && (data[1] & 255) <= 2) {
            int subtype = data[1] & 255;
            if (data.length < (subtype == 0 ? 3 : subtype == 1 ? 12 : 6))
                return opaque("Microsoft vendor advertisement", data, fields, "Truncated Swift Pair payload; required transport fields are missing.", SWIFT_SOURCE);
            fields.add(new Field("Advertised pairing transport", subtype == 0 ? "BLE" : subtype == 1 ? "BR/EDR; BLE discovery" : "BLE + BR/EDR, Secure Connections", "documented"));
            return new Result("Microsoft Swift Pair", "documented", fields, BluetoothAdvertisement.hex(Arrays.copyOfRange(data, 3, data.length)),
                    "Pairing advertisement detected; no pairing is initiated. Optional name, address and class bytes remain undecoded.", SWIFT_SOURCE);
        }
        // The vendor SDK emits this 27-byte layout, but company ID + shape cannot authenticate it.
        if (company == 0x05d6 && data.length == 27 && supportedJieliKind((data[4] & 255) >>> 4)
                && (data[4] & 15) <= 3 && batteryPlausible(data[12]) && batteryPlausible(data[13]) && batteryPlausible(data[14])) {
            fields.add(new Field("Candidate VID", String.format(Locale.ROOT, "0x%04X", (data[0] & 255) | ((data[1] & 255) << 8)), "inferred"));
            fields.add(new Field("Candidate PID", String.format(Locale.ROOT, "0x%04X", (data[2] & 255) | ((data[3] & 255) << 8)), "inferred"));
            String kind = switch ((data[4] & 255) >>> 4) {
                case 0 -> "Speaker class"; case 2 -> "TWS earphone class"; case 4 -> "Sound card class"; case 5 -> "Watch class";
                default -> "Unknown class";
            };
            fields.add(new Field("Candidate SDK device class", kind, "inferred"));
            fields.add(new Field("SDK type/flags byte", String.format(Locale.ROOT, "0x%02X", data[4] & 255), "observed"));
            StringBuilder address = new StringBuilder();
            for (int i=5; i<11; i++) { if(i>5)address.append(':'); address.append(String.format(Locale.ROOT,"%02X", data[i]&255)); }
            fields.add(new Field("Candidate RCSP address", address.toString(), "inferred"));
            fields.add(new Field("SDK connection byte", String.format(Locale.ROOT, "0x%02X", data[11] & 255), "observed"));
            for(int i=0; i<3; i++) {
                int value=data[12+i]&255, percentage=value&127;
                fields.add(new Field("Candidate battery slot " + (i+1), percentage == 0 ? "Not reported / zero field" : percentage + "%" + ((value&128)!=0 ? " (charging flag)" : ""), "inferred"));
            }
            fields.add(new Field("Candidate advertisement sequence", String.valueOf(data[15]&255), "inferred"));
            return new Result("Jieli RCSP-like", "inferred", fields,
                    BluetoothAdvertisement.hex(Arrays.copyOfRange(data,16,data.length)),
                    "Shape matches a vendor SDK advertisement. Fields are candidates, not verified model, hardware identity or battery state; firmware variants may differ.",
                    "https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/common/third_party_profile/jieli/rcsp/bt_trans_data/ble_rcsp_adv.c");
        }
        if (company == 0x0075 || company == 0x05d6) {
            String vendor = company == 0x0075 ? "Samsung" : "Jieli";
            if (data.length > 0) fields.add(new Field("Payload prefix", BluetoothAdvertisement.hex(Arrays.copyOfRange(data, 0, Math.min(4, data.length))), "observed"));
            addAddressMatch(fields, data, observedAddress);
            if (company == 0x05d6 && startsWith(data, new byte[]{8, 0, 'J', 'L', 'A', 'I', 'S', 'D', 'K'})) {
                fields.add(new Field("SDK tag", "JLAISDK", "documented"));
                return new Result("Jieli SDK tag", "documented", fields, BluetoothAdvertisement.hex(Arrays.copyOfRange(data, 9, data.length)),
                        "SDK tag observed; model, product ID, battery and RCSP variant are not established by this tag.", JIELI_SOURCE);
            }
            return opaque(vendor + " vendor advertisement", data, fields,
                    "Proprietary layout not verified. No model, battery, product ID or protocol is guessed from the company ID or prefix.", company == 0x05d6 ? JIELI_SOURCE : "");
        }
        return opaque(company == 6 ? "Microsoft vendor advertisement" : "Unrecognized manufacturer payload", data, fields,
                "No supported protocol signature; payload retained without interpretation.", "");
    }

    private static boolean supportedJieliKind(int kind) { return kind == 0 || kind == 2 || kind == 4 || kind == 5; }
    private static boolean batteryPlausible(byte value) { return (value & 127) <= 100; }
    private static Result opaque(String protocol, byte[] data, List<Field> fields, String note, String source) {
        return new Result(protocol, "observed", fields, BluetoothAdvertisement.hex(data), note, source);
    }
    static byte[] bytes(String hex) {
        if (hex == null || hex.length() > 3300 || (hex.length() & 1) != 0) return new byte[0];
        byte[] result = new byte[hex.length()/2];
        for (int i=0; i<result.length; i++) {
            int a = Character.digit(hex.charAt(i*2),16), b = Character.digit(hex.charAt(i*2+1),16);
            if (a < 0 || b < 0) return new byte[0];
            result[i] = (byte)((a << 4) | b);
        }
        return result;
    }
    private static void addAddressMatch(List<Field> fields, byte[] data, String address) {
        if (address == null || !address.matches("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}")) return;
        byte[] target = bytes(address.replace(":", ""));
        for (int i=0; i+6<=data.length; i++) {
            boolean forward=true, reverse=true;
            for (int j=0; j<6; j++) { forward &= data[i+j] == target[j]; reverse &= data[i+j] == target[5-j]; }
            if (forward || reverse) { fields.add(new Field("Observed scan address in payload", address + " at byte " + i + (forward ? " (same order)" : " (reverse order)"), "observed")); return; }
        }
    }
    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i=0; i<prefix.length; i++) if (data[i] != prefix[i]) return false;
        return true;
    }
    private static String deviceKind(int type) {
        return switch(type) {
            case 1 -> "Xbox One"; case 6 -> "iPhone"; case 7 -> "iPad"; case 8 -> "Android";
            case 9 -> "Windows desktop"; case 11 -> "Windows phone"; case 12 -> "Linux";
            case 13 -> "Windows IoT"; case 14 -> "Surface Hub"; case 15 -> "Windows laptop"; case 16 -> "Windows tablet";
            default -> "Unknown (" + type + ")";
        };
    }
}
