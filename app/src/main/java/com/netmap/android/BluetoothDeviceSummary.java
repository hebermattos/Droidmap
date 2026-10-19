package com.netmap.android;

import java.util.*;

final class BluetoothDeviceSummary {
    record Device(String name, String address, String transport, boolean observed, Integer rssi, Boolean connectable,
                  List<String> companies, List<String> protocols, Map<String,String> information,
                  int services, String inspection, int attempts) {}
    static String render(Device device) {
        StringBuilder text = new StringBuilder();
        text.append("Name: ").append(device.name.isEmpty() ? "Not announced" : device.name).append('\n');
        text.append("Address: ").append(device.address).append('\n');
        text.append("Transport: ").append(device.transport).append('\n');
        if (!device.observed) text.append("Presence: paired record only; not observed nearby\n");
        else if (device.rssi != null) text.append("Signal: ").append(device.rssi).append(" dBm (")
                .append(device.rssi >= -60 ? "strong" : device.rssi >= -80 ? "moderate" : "weak").append(")\n");
        if (device.connectable != null) text.append("BLE connection: ").append(device.connectable ? "Advertised as connectable" : "Not connectable; advertisement analysis only").append('\n');
        if (!device.companies.isEmpty()) text.append("Company IDs: ").append(String.join(", ", device.companies)).append(" (not verified hardware makers)\n");
        for (String protocol : device.protocols) text.append("Advertisement: ").append(protocol).append('\n');
        for (Map.Entry<String,String> info : device.information.entrySet()) text.append(info.getKey()).append(": ").append(info.getValue()).append(" (GATT reported)\n");
        if (device.services >= 0) text.append("GATT services found: ").append(device.services).append('\n');
        if (!device.inspection.isEmpty()) text.append("Inspection: ").append(device.inspection).append('\n');
        if (device.attempts > 0) text.append("Connection attempts: ").append(device.attempts).append('/').append(BluetoothGattRetry.MAX_ATTEMPTS).append('\n');
        return text.toString().trim();
    }
}
