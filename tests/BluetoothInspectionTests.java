package com.netmap.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class BluetoothInspectionTests {
    public static void main(String[] args) throws Exception {
        var selected = BluetoothInspectionQueue.eligible(List.of(
                new BluetoothInspectionQueue.Candidate("weak", true, true, true, -99),
                new BluetoothInspectionQueue.Candidate("strong", true, true, true, -50),
                new BluetoothInspectionQueue.Candidate("cached", false, true, true, -40),
                new BluetoothInspectionQueue.Candidate("beacon", true, true, false, -30),
                new BluetoothInspectionQueue.Candidate("classic", true, false, true, -20)));
        check(selected.equals(List.of("strong", "weak")), "eligibility and signal ordering");
        var queue = new BluetoothInspectionQueue(List.of("a", "a", "b", "c"));
        check(queue.total() == 3 && queue.next().equals("a"), "deduplicate targets");
        boolean blocked = false;
        try { queue.next(); } catch (IllegalStateException expected) { blocked = true; }
        check(blocked, "only one connection active");
        queue.complete(); check(queue.completed() == 1 && queue.next().equals("b"), "failure/completion can advance");
        check(queue.cancel().equals(List.of("b", "c")), "cancellation includes active and pending, excludes completed");
        check(queue.next() == null && queue.completed() == 1, "cancellation cannot restart pending devices");
        var empty = new BluetoothInspectionQueue(List.of()); check(empty.next() == null, "empty queue");
        List<String> tooMany = new ArrayList<>();
        for (int i=0; i<513; i++) tooMany.add("device"+i);
        boolean bounded = false;
        try { new BluetoothInspectionQueue(tooMany); } catch (IllegalArgumentException expected) { bounded = true; }
        check(bounded, "queue bound");
        var full = new BluetoothInspectionQueue(tooMany.subList(0, 512));
        int processed = 0;
        while (full.next() != null) { full.complete(); processed++; }
        check(processed == 512 && full.completed() == 512, "every bounded target is processed exactly once");
        BluetoothCatalog.load(new FileInputStream(args[0]));
        check(BluetoothAdvertisement.company(0x05d6).contains("Jieli"), "Jieli official identifier");
        check(BluetoothAdvertisement.company(0).contains("Ericsson"), "zero is an assigned ID, not unknown");
        check(!BluetoothAdvertisement.uuidName("00002902-0000-1000-8000-00805f9b34fb").isEmpty(), "descriptor names");
        check(BluetoothAdvertisement.readableInfo("0000180a-0000-1000-8000-00805f9b34fb", "00002a24-0000-1000-8000-00805f9b34fb"), "official label changes do not change read allowlist");
        check(BluetoothCatalog.uuid("00002a24-aaaa-1000-8000-00805f9b34fb").isEmpty(), "vendor UUID cannot inherit standard name");
        boolean malformed = false;
        try { BluetoothCatalog.load(new ByteArrayInputStream("C00000001\tGood\ninvalid\n".getBytes(StandardCharsets.UTF_8))); }
        catch (IOException expected) { malformed = true; }
        check(malformed && BluetoothAdvertisement.company(0x05d6).contains("Jieli"), "catalog replacement is atomic on malformed input");
        check(BluetoothGattStatus.describe(5).contains("Authentication"), "read authentication diagnosis");
        check(BluetoothGattStatus.describe(8).contains("Authorization") && BluetoothGattStatus.connection(8).contains("timeout"), "status meanings are operation-specific");
        check(BluetoothGattStatus.connection(133).contains("not specified"), "do not invent a reason for generic Android failures");
        check(BluetoothGattStatus.describe(12345).contains("12345"), "retain unknown status codes");
        System.out.println("PASS: Bluetooth inspection queue, cancellation, catalog and diagnostic tests");
    }
    private static void check(boolean value, String label) { if (!value) throw new AssertionError(label); }
}
