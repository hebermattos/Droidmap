package com.netmap.android;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Bounds-checked AD structures, including unknown types, without guessing device identity. */
final class BluetoothAdvertisement {
    record Field(int type, String hex) {}
    record Parsed(List<Field> fields, boolean truncated) {}

    static Parsed parse(byte[] bytes) {
        List<Field> fields = new ArrayList<>();
        if (bytes == null) return new Parsed(fields, false);
        int offset = 0;
        while (offset < bytes.length) {
            int length = bytes[offset++] & 255;
            if (length == 0) break;
            if (length > bytes.length - offset) return new Parsed(fields, true);
            int type = bytes[offset] & 255;
            fields.add(new Field(type, hex(bytes, offset + 1, length - 1)));
            offset += length;
        }
        return new Parsed(fields, false);
    }

    static String hex(byte[] bytes) {
        return bytes == null ? "" : hex(bytes, 0, bytes.length);
    }

    private static String hex(byte[] bytes, int offset, int length) {
        char[] out = new char[length * 2];
        char[] digits = "0123456789ABCDEF".toCharArray();
        for (int i = 0; i < length; i++) {
            int value = bytes[offset + i] & 255;
            out[i * 2] = digits[value >>> 4];
            out[i * 2 + 1] = digits[value & 15];
        }
        return new String(out);
    }

    static String iBeacon(int company, byte[] data) {
        if (company != 0x004c || data == null || data.length < 23 || data[0] != 2 || data[1] != 0x15) return "";
        String id = hex(data, 2, 16).toLowerCase(Locale.ROOT);
        String uuid = id.substring(0,8) + "-" + id.substring(8,12) + "-" + id.substring(12,16) + "-" + id.substring(16,20) + "-" + id.substring(20);
        return "iBeacon UUID " + uuid + "; major " + (((data[18] & 255) << 8) | (data[19] & 255))
                + "; minor " + (((data[20] & 255) << 8) | (data[21] & 255)) + "; measured power " + data[22] + " dBm";
    }

    static String eddystone(String uuid, byte[] data) {
        if (!"0000feaa-0000-1000-8000-00805f9b34fb".equals(uuid) || data == null || data.length == 0) return "";
        return switch (data[0] & 255) {
            case 0 -> data.length >= 18 ? "Eddystone UID; namespace " + hex(data, 2, 10) + "; instance " + hex(data, 12, 6) : "Truncated Eddystone UID";
            case 0x10 -> data.length >= 3 ? "Eddystone URL frame (raw service data retained)" : "Truncated Eddystone URL";
            case 0x20 -> data.length >= 14 ? "Eddystone telemetry frame" : "Truncated Eddystone telemetry";
            case 0x30 -> data.length >= 10 ? "Eddystone ephemeral identifier frame" : "Truncated Eddystone identifier";
            default -> "Unknown Eddystone frame";
        };
    }

    static String company(int id) {
        String assigned = BluetoothCatalog.company(id);
        if (!assigned.isEmpty()) return assigned;
        return switch (id) {
            case 0x004c -> "Apple";
            case 0x0075 -> "Samsung";
            case 0x0006 -> "Microsoft";
            case 0x00e0 -> "Google";
            case 0x05d6 -> "Zhuhai Jieli technology Co.,Ltd";
            case 0x0059 -> "Nordic Semiconductor";
            default -> "Unknown";
        };
    }

    static String uuidName(String uuid) {
        String assigned = BluetoothCatalog.uuid(uuid);
        if (!assigned.isEmpty()) return assigned;
        if (uuid == null || !uuid.toLowerCase(Locale.ROOT).endsWith("-0000-1000-8000-00805f9b34fb")) return "";
        return switch (uuid.substring(0, 8).toLowerCase(Locale.ROOT)) {
            case "00001800" -> "Generic Access";
            case "00001801" -> "Generic Attribute";
            case "0000180a" -> "Device Information";
            case "0000180d" -> "Heart Rate";
            case "0000180f" -> "Battery";
            case "00001812" -> "Human Interface Device";
            case "0000181a" -> "Environmental Sensing";
            case "00001101" -> "Serial Port";
            case "0000110a" -> "Audio Source";
            case "0000110b" -> "Audio Sink";
            case "0000110e" -> "AV Remote Control";
            case "0000111e" -> "Handsfree";
            case "00002a00" -> "Device Name";
            case "00002a19" -> "Battery Level";
            case "00002a24" -> "Model Number";
            case "00002a25" -> "Serial Number";
            case "00002a26" -> "Firmware Revision";
            case "00002a27" -> "Hardware Revision";
            case "00002a28" -> "Software Revision";
            case "00002a29" -> "Manufacturer Name";
            default -> "";
        };
    }

    static boolean readableInfo(String service, String characteristic) {
        if (characteristic == null) return false;
        return (service.equals("00001800-0000-1000-8000-00805f9b34fb") && characteristic.equals("00002a00-0000-1000-8000-00805f9b34fb"))
                || (service.equals("0000180f-0000-1000-8000-00805f9b34fb") && characteristic.equals("00002a19-0000-1000-8000-00805f9b34fb"))
                || (service.equals("0000180a-0000-1000-8000-00805f9b34fb") && characteristic.matches("00002a2[4-9]-0000-1000-8000-00805f9b34fb"));
    }

    static String value(String uuid, byte[] bytes) {
        if (bytes == null) return "";
        if ("00002a19-0000-1000-8000-00805f9b34fb".equals(uuid))
            return bytes.length == 1 && (bytes[0] & 255) <= 100 ? (bytes[0] & 255) + "%" : "Invalid battery value";
        return new String(bytes, 0, Math.min(bytes.length, 512), StandardCharsets.UTF_8)
                .replaceAll("[\\p{Cntrl}]", " ").trim();
    }
}
