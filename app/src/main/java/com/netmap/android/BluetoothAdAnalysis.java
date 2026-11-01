package com.netmap.android;

import java.util.*;

/** Manufacturer-independent AD structure inspection; byte evidence is always retained. */
final class BluetoothAdAnalysis {
    record Entry(int type, String label, String hex, String detail, String warning) {}
    static List<Entry> inspect(byte[] raw) {
        var parsed = BluetoothAdvertisement.parse(raw);
        List<Entry> results = new ArrayList<>();
        for (var field : parsed.fields()) {
            int type = field.type(), length = field.hex().length() / 2;
            String label = switch (type) {
                case 0x01 -> "Flags";
                case 0x02, 0x03 -> "16-bit service UUIDs";
                case 0x04, 0x05 -> "32-bit service UUIDs";
                case 0x06, 0x07 -> "128-bit service UUIDs";
                case 0x08, 0x09 -> "Local name";
                case 0x0A -> "TX power";
                case 0x16 -> "16-bit service data";
                case 0x20 -> "32-bit service data";
                case 0x21 -> "128-bit service data";
                case 0xFF -> "Manufacturer data";
                default -> "Unknown AD type";
            };
            int width = switch (type) {
                case 0x02, 0x03 -> 2;
                case 0x04, 0x05 -> 4;
                case 0x06, 0x07 -> 16;
                default -> 0;
            };
            int min = switch (type) {
                case 0x01, 0x0A -> 1;
                case 0x16, 0xFF -> 2;
                case 0x20 -> 4;
                case 0x21 -> 16;
                default -> 0;
            };
            boolean invalid = length < min || (width > 0 && (length == 0 || length % width != 0))
                    || ((type == 0x01 || type == 0x0A) && length != 1);
            String detail = "";
            if (!invalid) {
                if (type == 0xFF) detail = "Assigned company ID (little-endian): 0x" + field.hex().substring(2,4) + field.hex().substring(0,2);
                else if (type == 0x16 || type == 0x20 || type == 0x21) detail = "Service UUID prefix: " + field.hex().substring(0, min * 2) + " (raw little-endian)";
                else if (width != 0) detail = (length / width) + " advertised UUID(s), " + (width * 8) + "-bit; raw bytes retained";
                else if (type == 0x01) detail = "Flags bitfield: 0x" + field.hex();
                else if (type == 0x0A) detail = "TX power: " + (byte)Integer.parseInt(field.hex(),16) + " dBm";
            }
            results.add(new Entry(type,label,field.hex(),detail,invalid ? "Invalid AD field length" : ""));
        }
        if (parsed.truncated()) results.add(new Entry(-1,"Truncated AD structure",BluetoothAdvertisement.hex(raw),"","Declared length exceeds available bytes"));
        return Collections.unmodifiableList(results);
    }
}
