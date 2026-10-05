package com.netmap.android;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

/** Shared cancellation, socket ownership and budgets for all protocol probes. */
final class ProbeContext {
    final ScanPlan plan;
    final DeviceEvidence evidence;
    private final Set<Closeable> active;
    private final LongSupplier deadline;
    private final BooleanSupplier stopRequested;

    ProbeContext(
            ScanPlan plan,
            DeviceEvidence evidence,
            Set<Closeable> active,
            LongSupplier deadline,
            BooleanSupplier stopRequested) {
        this.plan = plan;
        this.evidence = evidence;
        this.active = active;
        this.deadline = deadline;
        this.stopRequested = stopRequested;
    }

    boolean stopped() {
        return stopRequested.getAsBoolean();
    }

    void track(Closeable socket) {
        active.add(socket);
    }

    void untrack(Closeable socket) {
        active.remove(socket);
    }

    int remainingTimeout(int maximum) throws SocketTimeoutException {
        long remaining = TimeUnit.NANOSECONDS.toMillis(deadline.getAsLong() - System.nanoTime());
        if (stopped() || remaining <= 0) throw new SocketTimeoutException();
        return (int) Math.max(1, Math.min(maximum, remaining));
    }

    byte[] receive(Socket socket, int limit) throws IOException {
        long until =
                Math.min(
                        deadline.getAsLong(),
                        System.nanoTime()
                                + TimeUnit.MILLISECONDS.toNanos(
                                        plan.mode == ScanPlan.Mode.COMPLETE ? 1800 : 900));
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[2048];
        while (!stopped() && result.size() < limit && System.nanoTime() < until) {
            socket.setSoTimeout(
                    (int)
                            Math.max(
                                    1,
                                    Math.min(
                                            500,
                                            TimeUnit.NANOSECONDS.toMillis(
                                                    until - System.nanoTime()))));
            int count;
            try {
                count =
                        socket.getInputStream()
                                .read(buffer, 0, Math.min(buffer.length, limit - result.size()));
            } catch (SocketTimeoutException e) {
                break;
            }
            if (count < 0) break;
            result.write(buffer, 0, count);
        }
        return result.toByteArray();
    }

    String read(String host, int port, String request, int limit) {
        return new String(
                readBytes(
                        host,
                        port,
                        request == null ? null : request.getBytes(StandardCharsets.US_ASCII),
                        limit),
                StandardCharsets.UTF_8);
    }

    byte[] readBytes(String host, int port, byte[] request, int limit) {
        if (stopped()) return new byte[0];
        try (Socket socket = new Socket()) {
            active.add(socket);
            try {
                if (stopped()) return new byte[0];
                socket.connect(new InetSocketAddress(host, port), remainingTimeout(500));
                long readDeadline =
                        Math.min(
                                deadline.getAsLong(),
                                System.nanoTime()
                                        + TimeUnit.MILLISECONDS.toNanos(
                                                plan.mode == ScanPlan.Mode.COMPLETE ? 1800 : 900));
                if (request != null) socket.getOutputStream().write(request);
                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buffer = new byte[2048];
                while (!stopped() && result.size() < limit && System.nanoTime() < readDeadline) {
                    socket.setSoTimeout(
                            (int)
                                    Math.max(
                                            1,
                                            Math.min(
                                                    500,
                                                    TimeUnit.NANOSECONDS.toMillis(
                                                            readDeadline - System.nanoTime()))));
                    int count;
                    try {
                        count =
                                socket.getInputStream()
                                        .read(
                                                buffer,
                                                0,
                                                Math.min(buffer.length, limit - result.size()));
                    } catch (SocketTimeoutException e) {
                        break;
                    }
                    if (count < 0) break;
                    result.write(buffer, 0, count);
                    if (request == null && result.toString("UTF-8").contains("\n")) break;
                }
                return result.toByteArray();
            } finally {
                active.remove(socket);
            }
        } catch (IOException | SecurityException e) {
            return new byte[0];
        }
    }
}
