package com.netmap.android;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.zip.DeflaterOutputStream;

/** Lossless two-byte storage per planned check; no Result object retained per connection. */
final class PackedScanResults extends AbstractList<TcpScanner.Result> {
    private static final TcpScanner.State[] STATES = TcpScanner.State.values();
    private final ScanPlan plan;
    private final short[][] records;
    private final Map<String,Integer> hostIndex = new HashMap<>();
    private final int[] portIndex = new int[65536];
    private int completed;

    PackedScanResults(ScanPlan plan) {
        this.plan = plan;
        records = new short[plan.hosts.size()][plan.ports.size()];
        Arrays.fill(portIndex, -1);
        for (int i = 0; i < plan.hosts.size(); i++) hostIndex.put(plan.hosts.get(i), i);
        for (int i = 0; i < plan.ports.size(); i++) portIndex[plan.ports.get(i)] = i;
    }

    @Override public synchronized boolean add(TcpScanner.Result result) {
        Integer host = hostIndex.get(result.host);
        int port = result.port > 0 && result.port < portIndex.length ? portIndex[result.port] : -1;
        if (host == null || port < 0 || result.attempts < 1 || result.attempts > 2
                || result.timeoutMs < 100 || result.timeoutMs > 3000)
            throw new IllegalArgumentException("Invalid packed TCP result");
        if (records[host][port] != 0) throw new IllegalStateException("Duplicate TCP check");
        records[host][port] = (short)((result.timeoutMs << 4) | (result.attempts << 2) | result.state.ordinal());
        completed++;
        return true;
    }

    @Override public synchronized int size() { return completed; }

    @Override public TcpScanner.Result get(int index) {
        if (index < 0 || index >= size()) throw new IndexOutOfBoundsException();
        Iterator<TcpScanner.Result> iterator = iterator();
        for (int i = 0; i < index; i++) iterator.next();
        return iterator.next();
    }

    @Override public Iterator<TcpScanner.Result> iterator() {
        return new Iterator<TcpScanner.Result>() {
            private int cursor;
            private final int total = plan.hosts.size() * plan.ports.size();
            private void skip() {
                while (cursor < total && records[cursor / plan.ports.size()][cursor % plan.ports.size()] == 0) cursor++;
            }
            @Override public boolean hasNext() { skip(); return cursor < total; }
            @Override public TcpScanner.Result next() {
                if (!hasNext()) throw new NoSuchElementException();
                int host = cursor / plan.ports.size(), port = cursor % plan.ports.size();
                int record = records[host][port] & 0xffff;
                cursor++;
                return new TcpScanner.Result(plan.hosts.get(host), plan.ports.get(port),
                        STATES[record & 3], (record >>> 2) & 3, record >>> 4);
            }
        };
    }

    /** Identification/report cards need every open port and one reachability witness per host. */
    List<TcpScanner.Result> evidenceChecks() {
        List<TcpScanner.Result> result = new ArrayList<>();
        Set<String> closed = new HashSet<>();
        for (TcpScanner.Result check : this) {
            if (check.state == TcpScanner.State.OPEN
                    || (check.state == TcpScanner.State.CLOSED && closed.add(check.host))) result.add(check);
        }
        return result;
    }

    /** One deflate stream per host, in selected-port order; zero denotes an unfinished check. */
    String encodedHost(int host) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DeflaterOutputStream compressed = new DeflaterOutputStream(bytes)) {
            byte[] chunk = new byte[4096];
            int used = 0;
            for (short value : records[host]) {
                chunk[used++] = (byte)((value & 0xffff) >>> 8);
                chunk[used++] = (byte)value;
                if (used == chunk.length) { compressed.write(chunk); used = 0; }
            }
            if (used > 0) compressed.write(chunk, 0, used);
        }
        return Base64.getEncoder().encodeToString(bytes.toByteArray());
    }
}
