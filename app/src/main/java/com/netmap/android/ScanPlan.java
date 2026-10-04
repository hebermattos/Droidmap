package com.netmap.android;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/** Literal private IPv4 targets only; caps work before any socket is opened. */
public final class ScanPlan {
    public enum Mode {
        FAST(0, 20, 6, 4), COMPLETE(1, 60, 12, 8);
        public final int retries, identificationSeconds, discoverySeconds, fingerprintLimit;
        Mode(int retries,int identificationSeconds,int discoverySeconds,int fingerprintLimit) {
            this.retries=retries; this.identificationSeconds=identificationSeconds; this.discoverySeconds=discoverySeconds; this.fingerprintLimit=fingerprintLimit;
        }
        public int nextTimeout(int timeout) { return Math.min(3000,timeout*2); }
    }
    public static final String FAST_PORTS="21,22,23,53,80,139,443,445,554,1080,1883,3389,5060,8000,8009,8080,8443,8888,9100";
    public static final String COMPLETE_PORTS=FAST_PORTS+",81,135,389,515,631,989,990,1433,1521,3306,5432,5900,5985,5986,8001,8081,8090,9000,9090,10000";
    public final Mode mode;
    public final List<String> hosts;
    public final List<Integer> ports;
    public final int timeoutMs;
    public final boolean adaptive;
    public ScanPlan(String target, String portText, int timeoutMs) { this(target,portText,timeoutMs,Mode.FAST); }
    public ScanPlan(String target, String portText, int timeoutMs,Mode mode) { this(target,portText,timeoutMs,mode,false); }
    public ScanPlan(String target, String portText, int timeoutMs,Mode mode,boolean adaptive) {
        this.adaptive=adaptive;
        this.mode=java.util.Objects.requireNonNull(mode);
        hosts = parseHosts(target);
        ports = parsePorts(portText);
        if (timeoutMs < 100 || timeoutMs > 3000) throw new IllegalArgumentException("Timeout must be 100–3000 ms.");
        this.timeoutMs = timeoutMs;
    }
    public static List<String> parseHosts(String input) {
        String[] parts = input.trim().split("/", -1);
        if (parts.length > 2) throw new IllegalArgumentException("Enter a private IPv4 address or /24–/32 network.");
        long address = ipv4(parts[0]);
        int prefix = parts.length == 1 ? 32 : number(parts[1]);
        if (prefix < 24 || prefix > 32) throw new IllegalArgumentException("Network prefix must be /24–/32 (at most 256 addresses).");
        long mask = (0xffffffffL << (32 - prefix)) & 0xffffffffL;
        long first = address & mask;
        long last = first | (~mask & 0xffffffffL);
        if (!isPrivate(first) || !isPrivate(last)) throw new IllegalArgumentException("Use a private network: 10.x.x.x, 172.16–31.x.x or 192.168.x.x.");
        if (prefix <= 30) { first++; last--; }
        List<String> hosts = new ArrayList<>();
        for (long ip = first; ip <= last; ip++) hosts.add(format(ip));
        return java.util.Collections.unmodifiableList(hosts);
    }
    static long ipv4(String text) {
        String[] octets = text.split("\\.", -1);
        if (octets.length != 4) throw new IllegalArgumentException("Enter a literal IPv4 address.");
        long result = 0;
        for (String octet : octets) {
            int value = number(octet);
            if (value > 255 || octet.length() > 3) throw new IllegalArgumentException("Invalid IPv4 address.");
            result = (result << 8) | value;
        }
        return result;
    }
    private static boolean isPrivate(long ip) {
        return (ip >>> 24) == 10 || (ip >>> 20) == 0xac1 || (ip >>> 16) == 0xc0a8;
    }
    private static String format(long ip) {
        return (ip >>> 24) + "." + ((ip >>> 16) & 255) + "." + ((ip >>> 8) & 255) + "." + (ip & 255);
    }
    private static int number(String value) {
        if (!value.matches("[0-9]{1,5}")) throw new IllegalArgumentException("Invalid numeric value: " + value);
        return Integer.parseInt(value);
    }
    public static List<Integer> parsePorts(String text) {
        TreeSet<Integer> ports = new TreeSet<>();
        for (String token : text.split(",", -1)) {
            String[] range = token.trim().split("-", -1);
            if (range.length > 2) throw new IllegalArgumentException("Use ports such as 22,80,443,8000-8010.");
            int start = number(range[0].trim());
            int end = range.length == 2 ? number(range[1].trim()) : start;
            if (start < 1 || end > 65535 || end < start || end - start >= 256) throw new IllegalArgumentException("Use 1–65535 and at most 256 distinct ports.");
            for (int p = start; p <= end; p++) ports.add(p);
            if (ports.size() > 256) throw new IllegalArgumentException("Select at most 256 distinct ports.");
        }
        return java.util.Collections.unmodifiableList(new ArrayList<>(ports));
    }
}
