package com.netmap.android;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;

/** Reads existing link-layer observations after TCP checks; never requests root. */
final class Ipv4MacDiscovery {
    static List<String> collect(String iface, Predicate<String> onLink, DeviceEvidence evidence,
            BooleanSupplier cancelled, boolean legacyArp) {
        List<String> notices = new ArrayList<>();
        if (iface == null || !iface.matches("[A-Za-z0-9_.-]{1,32}") || cancelled.getAsBoolean())
            return notices;
        Process process = null;
        ExecutorService reader = Executors.newSingleThreadExecutor();
        boolean available = false;
        try {
            process = new ProcessBuilder("/system/bin/ip", "-4", "neigh", "show", "dev", iface)
                    .redirectErrorStream(true).start();
            Process command = process;
            Future<String> output = reader.submit(() -> NmapRunner.readBounded(command.getInputStream(), 65536));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
            while (!process.waitFor(50, TimeUnit.MILLISECONDS)) {
                if (cancelled.getAsBoolean() || System.nanoTime() >= deadline)
                    throw new IOException("Neighbor read cancelled or timed out");
            }
            String text = output.get(200, TimeUnit.MILLISECONDS);
            if (process.exitValue() != 0) throw new IOException("Neighbor table unavailable");
            available = true;
            record(text, iface, onLink, evidence, cancelled, false);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
            // Android can deny netlink access; other identification methods remain active.
        } finally {
            if (process != null) {
                process.destroyForcibly();
                try { process.getInputStream().close(); } catch (IOException ignored) { }
            }
            reader.shutdownNow();
        }
        // Android 10+ prohibits /proc/net; only try the legacy file on older devices.
        if (!available && legacyArp && !cancelled.getAsBoolean()) {
            try (InputStream input = new FileInputStream("/proc/net/arp")) {
                String text = NmapRunner.readBounded(input, 65536);
                record(text, iface, onLink, evidence, cancelled, true);
                available = true;
            } catch (IOException | SecurityException ignored) { }
        }
        if (!available && !cancelled.getAsBoolean())
            notices.add("IPv4 MAC table unavailable on this Android device; NetBIOS and Nmap observations remain available when reported.");
        return notices;
    }

    private static void record(String text, String iface, Predicate<String> onLink,
            DeviceEvidence evidence, BooleanSupplier cancelled, boolean arp) {
        int lines = 0;
        for (String line : text.split("\n")) {
            if (cancelled.getAsBoolean() || lines++ >= 512) break;
            recordLine(line, iface, onLink, evidence, arp);
        }
    }

    static void recordLine(String line, String iface, Predicate<String> onLink,
            DeviceEvidence evidence, boolean arp) {
        String[] parts = line.trim().split("\\s+");
        if (parts.length < 2) return;
        String ip = parts[0], mac = "", state = "", device = iface;
        try { ScanPlan.ipv4(ip); } catch (IllegalArgumentException e) { return; }
        if (arp) {
            if (parts.length != 6) return;
            try {
                if (Integer.decode(parts[1]) != 1 || (Integer.decode(parts[2]) & 2) == 0) return;
            } catch (NumberFormatException e) { return; }
            device = parts[5]; mac = parts[3]; state = "Cached ARP entry";
        } else {
            state = parts[parts.length - 1];
            if (!Arrays.asList("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP").contains(state)) return;
            for (int i = 1; i + 1 < parts.length; i++) {
                if (parts[i].equals("dev")) device = parts[i + 1];
                if (parts[i].equals("lladdr")) mac = parts[i + 1];
            }
        }
        mac = MacAddresses.normalize(mac);
        if (!Objects.equals(iface, device) || !evidence.isAllowed(ip) || !onLink.test(ip) || mac.isEmpty()) return;
        String source = arp ? "IPv4 ARP cache" : "IPv4 neighbor";
        evidence.add(ip, source, "neighborMac", mac);
        evidence.add(ip, source, "neighborState", state);
        evidence.add(ip, source, "networkInterface", iface);
        evidence.add(ip, source, "reachabilityNote", "Cached link-layer observation; current reachability unverified");
    }
}
