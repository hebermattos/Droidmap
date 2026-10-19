package com.netmap.android;

final class BluetoothGattStatus {
    static String connection(int status) {
        return switch (status) {
            case 0 -> "Disconnected without a stack error (0)";
            case 8 -> "Link timeout (8)";
            case 19 -> "Remote device terminated the connection (19)";
            case 22 -> "Local host terminated the connection (22)";
            case 62 -> "Connection could not be established (62)";
            case 133 -> "Android GATT error (133); cause not specified by stack";
            case 147 -> "Connection timeout (147)";
            default -> "Connection status " + status;
        };
    }
    static String describe(int status) {
        return switch (status) {
            case 0 -> "Success (0)";
            case 2 -> "Read not permitted (2)";
            case 5 -> "Authentication required (5)";
            case 6 -> "Request not supported (6)";
            case 8 -> "Authorization required (8)";
            case 15 -> "Encryption required (15)";
            case 133 -> "Android GATT error (133); cause not specified by stack";
            case 143 -> "Connection congested (143)";
            case 147 -> "Connection timeout (147)";
            case 257 -> "GATT operation failed (257)";
            default -> "GATT status " + status;
        };
    }
}
