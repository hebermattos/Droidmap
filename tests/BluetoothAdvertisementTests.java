package com.netmap.android;

public final class BluetoothAdvertisementTests {
    public static void main(String[] args) {
        check(BluetoothAdvertisement.parse(null).fields().isEmpty(), "null advertisement");
        check(!BluetoothAdvertisement.parse(new byte[]{0}).truncated(), "padding");
        byte[] sample = java.util.HexFormat.of().parseHex("02010605FF75000102");
        var parsed = BluetoothAdvertisement.parse(sample);
        check(parsed.fields().size() == 2 && !parsed.truncated(), "AD structures");
        check(parsed.fields().get(1).type() == 255 && parsed.fields().get(1).hex().equals("75000102"), "manufacturer bytes");
        check(BluetoothAdvertisement.parse(new byte[]{5, (byte)255, 1}).truncated(), "short length");
        check(BluetoothAdvertisement.parse(new byte[]{(byte)255, 1}).truncated(), "unsigned length");
        check(BluetoothAdvertisement.parse(new byte[]{1, 99}).fields().get(0).hex().isEmpty(), "empty unknown field");
        check(BluetoothAdvertisement.hex(new byte[]{0, (byte)255}).equals("00FF"), "unsigned hex");
        check(BluetoothAdvertisement.company(0x75).equals("Samsung"), "Samsung assigned company ID");
        check(BluetoothAdvertisement.company(0x1234).equals("Unknown"), "unknown company");
        check(BluetoothAdvertisement.uuidName("custom").isEmpty(), "custom UUID");
        String info = "0000180a-0000-1000-8000-00805f9b34fb";
        String model = "00002a24-0000-1000-8000-00805f9b34fb";
        check(BluetoothAdvertisement.readableInfo(info, model), "device information allowlist");
        check(!BluetoothAdvertisement.readableInfo(info, info), "service UUID is not a readable information characteristic");
        check(!BluetoothAdvertisement.readableInfo("custom", model), "same characteristic in vendor service not auto-read");
        check(!BluetoothAdvertisement.readableInfo(info, "00002a19-0000-1000-8000-00805f9b34fb"), "battery only in battery service");
        check(BluetoothAdvertisement.value("00002a19-0000-1000-8000-00805f9b34fb", new byte[]{100}).equals("100%"), "battery");
        check(BluetoothAdvertisement.value("00002a19-0000-1000-8000-00805f9b34fb", new byte[]{(byte)255}).equals("Invalid battery value"), "invalid battery");
        check(BluetoothAdvertisement.value(model, new byte[]{65,0,66}).equals("A B"), "display control characters");
        byte[] beacon = java.util.HexFormat.of().parseHex("021500112233445566778899aabbccddeeff00010002c5");
        check(BluetoothAdvertisement.iBeacon(0x4c, beacon).contains("major 1; minor 2; measured power -59"), "iBeacon fields");
        check(BluetoothAdvertisement.iBeacon(0x75, beacon).isEmpty(), "vendor payload is not an Apple beacon");
        check(BluetoothAdvertisement.iBeacon(0x4c, new byte[]{2, 21}).isEmpty(), "truncated iBeacon");
        check(BluetoothAdvertisement.eddystone("0000feaa-0000-1000-8000-00805f9b34fb", new byte[]{0}).startsWith("Truncated"), "truncated Eddystone");
        java.util.Random random = new java.util.Random(7);
        for (int i = 0; i < 10000; i++) {
            byte[] bytes = new byte[random.nextInt(1651)]; random.nextBytes(bytes);
            BluetoothAdvertisement.parse(bytes);
        }
        System.out.println("Bluetooth advertisement tests passed (including 10,000 malformed/random packets)");
    }
    private static void check(boolean condition, String label) { if (!condition) throw new AssertionError(label); }
}
