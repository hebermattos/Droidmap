package com.netmap.android;

import java.util.HexFormat;

public final class BluetoothAdAnalysisTests {
    public static void main(String[] args) {
        var example = BluetoothAdAnalysis.inspect(HexFormat.of().parseHex("02010605FF75000102"));
        check(example.size() == 2, "valid field count");
        check(example.get(1).detail().contains("0x0075"), "little-endian company ID");
        check(example.get(1).warning().isEmpty(), "valid manufacturer data");
        var unknown = BluetoothAdAnalysis.inspect(new byte[]{2, 0x70, 42});
        check(unknown.get(0).label().equals("Unknown AD type"), "unknown type preserved");
        check(unknown.get(0).hex().equals("2A"), "unknown raw data");
        var malformed = BluetoothAdAnalysis.inspect(new byte[]{2, 0x0A, 1, 2, (byte)0xFF, 1});
        check(malformed.get(1).warning().contains("Invalid"), "short manufacturer data");
        var truncated = BluetoothAdAnalysis.inspect(new byte[]{4, 0x01, 1});
        check(truncated.get(0).warning().contains("exceeds"), "truncated AD warning");
        var uuid = BluetoothAdAnalysis.inspect(new byte[]{4, 0x03, 0x0F, 0x18, 1});
        check(uuid.get(0).warning().contains("Invalid"), "misaligned UUID data");
        java.util.Random random = new java.util.Random(42);
        for (int i = 0; i < 10000; i++) {
            byte[] bytes = new byte[random.nextInt(512)];
            random.nextBytes(bytes);
            BluetoothAdAnalysis.inspect(bytes);
        }
        System.out.println("Generic BLE AD analysis tests passed");
    }
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }
}
