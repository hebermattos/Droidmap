package com.netmap.android;

import java.io.*;
import java.util.*;
import java.util.zip.InflaterInputStream;

/** Large result storage and export round trips under a fixed heap budget. */
public final class PackedScanTests {
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    public static void main(String[] args) throws Exception {
        ScanPlan plan = new ScanPlan("192.168.0.0/24", ScanPlan.ALL_PORTS, 200);
        PackedScanResults full = new PackedScanResults(plan);
        for (String host : plan.hosts) for (int port : plan.ports) {
            TcpScanner.State state = port == 1 ? TcpScanner.State.OPEN : port == 2 ? TcpScanner.State.ERROR
                    : port == 3 ? TcpScanner.State.NO_RESPONSE : TcpScanner.State.CLOSED;
            full.add(new TcpScanner.Result(host, port, state, port == 3 ? 2 : 1, port == 3 ? 3000 : 200));
        }
        check(full.size() == 16645890, "Retain every /24 TCP connection in bounded storage");
        check(full.evidenceChecks().size() == 508, "Retain every open port and every responding host");
        for (int host : new int[]{0,253}) {
            byte[] encoded = Base64.getDecoder().decode(full.encodedHost(host));
            check(encoded.length < 1024, "Repeated states compress without losing port details");
            try (DataInputStream in = new DataInputStream(new InflaterInputStream(new ByteArrayInputStream(encoded)))) {
                for (int port = 1; port <= 65535; port++) {
                    int word = in.readUnsignedShort();
                    int state = port == 1 ? 0 : port == 2 ? 3 : port == 3 ? 2 : 1;
                    check((word & 3) == state, "Every state round trips");
                    check(((word >>> 2) & 3) == (port == 3 ? 2 : 1), "Attempts round trip");
                    check((word >>> 4) == (port == 3 ? 3000 : 200), "Final timeout round trips");
                }
                check(in.read() == -1, "Exactly two bytes per selected port");
            }
        }
        PackedScanResults partial = new PackedScanResults(new ScanPlan("10.0.0.0/31", "80,443", 200));
        partial.add(new TcpScanner.Result("10.0.0.1",443,TcpScanner.State.OPEN,1,200));
        check(partial.size()==1 && partial.get(0).port==443 && partial.get(0).host.equals("10.0.0.1"), "Sparse cancelled results retain only completed checks");
        try (DataInputStream in = new DataInputStream(new InflaterInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(partial.encodedHost(0)))))) {
            check(in.readUnsignedShort()==0 && in.readUnsignedShort()==0, "Unfinished checks are never marked closed");
        }
        PackedScanResults skipped=new PackedScanResults(new ScanPlan("10.0.0.0/31","80,443",200));
        skipped.add(new TcpScanner.Result("10.0.0.1",80,TcpScanner.State.SKIPPED,0,0));
        check(skipped.get(0).state==TcpScanner.State.SKIPPED && skipped.get(0).attempts==0,
                "Skipped ports remain distinguishable from timeout and incomplete checks");
        try(DataInputStream in=new DataInputStream(new InflaterInputStream(new ByteArrayInputStream(
                Base64.getDecoder().decode(skipped.encodedHost(1)))))) {
            check(in.readUnsignedShort()==0xffff && in.readUnsignedShort()==0,
                    "Skipped and unfinished packed states have different encodings");
        }
        System.out.println("PASS: packed scan results (16,645,890 connections, exact export, retries, partial results, 96 MiB heap)");
    }
}
