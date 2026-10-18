package com.netmap.android;

import java.net.InetAddress;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.function.IntConsumer;

/** Best-effort, non-root host reachability before TCP ports. Silence is not proof of absence. */
final class HostDiscovery {
    static Set<String> discover(ScanPlan plan, BooleanSupplier cancelled, IntConsumer progress)
            throws InterruptedException {
        Set<String> responding = ConcurrentHashMap.newKeySet();
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(32, plan.hosts.size()));
        AtomicInteger done = new AtomicInteger();
        int timeout = Math.max(100, Math.min(500, plan.timeoutMs));
        try {
            for (String host : plan.hosts) {
                if (cancelled.getAsBoolean()) break;
                pool.execute(() -> {
                    if (!cancelled.getAsBoolean()) {
                        try {
                            if (InetAddress.getByName(ScanPlan.stripZone(host)).isReachable(timeout))
                                responding.add(host);
                        } catch (Exception ignored) {
                            // Android may block ICMP; the TCP scan is still authoritative.
                        }
                    }
                    progress.accept(done.incrementAndGet());
                });
            }
            pool.shutdown();
            while (!pool.awaitTermination(100, TimeUnit.MILLISECONDS)) {
                if (cancelled.getAsBoolean()) {
                    pool.shutdownNow();
                    break;
                }
            }
        } finally {
            pool.shutdownNow();
        }
        return Collections.unmodifiableSet(responding);
    }
}
