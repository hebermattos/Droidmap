package com.netmap.android;

import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Runs without Android SDK; fails with nonzero exit status on any assertion. */
public final class ScannerTests {
    private static int assertions;
    private static void check(boolean condition, String message) {
        assertions++; if (!condition) throw new AssertionError(message);
    }
    private static void rejects(Runnable action) {
        try { action.run(); throw new AssertionError("Expected invalid input rejection"); }
        catch (IllegalArgumentException expected) { assertions++; }
    }
    public static void main(String[] args) throws Exception {
        check(ScanPlan.parseHosts("192.168.0.109").equals(List.of("192.168.0.109")), "Single IP");
        List<String> hosts = ScanPlan.parseHosts("192.168.0.109/24");
        check(hosts.size() == 254 && hosts.get(0).equals("192.168.0.1") && hosts.get(253).equals("192.168.0.254"), "CIDR normalization");
        check(ScanPlan.parseHosts("10.0.0.0/31").size() == 2, "Point to point");
        check(ScanPlan.wifiNetworkTarget("192.168.0.109", 24).equals("192.168.0.0/24"), "All Wi-Fi IPs normalizes the network");
        check(ScanPlan.wifiNetworkTarget("10.0.0.130", 25).equals("10.0.0.128/25"), "All Wi-Fi IPs preserves actual prefix");
        check(ScanPlan.parseHosts(ScanPlan.wifiNetworkTarget("10.0.0.130", 25)).size() == 126, "All usable addresses selected");
        check(ScanPlan.wifiNetworkTarget("10.0.0.1", 32).equals("10.0.0.1/32"), "Single-host Wi-Fi subnet");
        rejects(() -> ScanPlan.wifiNetworkTarget("10.0.0.1", 23));
        rejects(() -> ScanPlan.wifiNetworkTarget("8.8.8.8", 24));
        rejects(() -> ScanPlan.wifiNetworkTarget("fe80::1", 64));
        check(ScanPlan.parseHosts("172.31.255.255/32").size() == 1, "Private 172 boundary");
        for (String bad : List.of("8.8.8.8", "172.32.0.1", "172.15.0.1", "127.0.0.1", "192.168.0.0/23", "192.168.0.1/33", "192.168.0.256", "hostname", "192.168.0.1/", "192.168.0.1/24/24", "-1.2.3.4")) rejects(() -> ScanPlan.parseHosts(bad));
        check(ScanPlan.parsePorts("443,80,80,21-23").equals(List.of(21,22,23,80,443)), "Ports sorted and deduplicated");
        check(ScanPlan.parsePorts("1-256").size() == 256, "Port cap boundary");
        for (String bad : List.of("", "80,", "0", "65536", "90-80", "1-257", "1-256,300", "a", "1-2-3")) rejects(() -> ScanPlan.parsePorts(bad));
        rejects(() -> new ScanPlan("10.0.0.1", "80", 99));
        rejects(() -> new ScanPlan("10.0.0.1", "80", 3001));
        TcpScanner scanner = new TcpScanner();
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            check(scanner.probe("127.0.0.1", server.getLocalPort(), 500) == TcpScanner.State.OPEN, "Real TCP connection");
            int closed = server.getLocalPort(); server.close();
            check(scanner.probe("127.0.0.1", closed, 500) == TcpScanner.State.CLOSED, "Real TCP refusal");
        }
        AtomicInteger peak = new AtomicInteger(), active = new AtomicInteger(), completed = new AtomicInteger();
        TcpScanner bounded = new TcpScanner((host, port, timeout) -> {
            int count = active.incrementAndGet(); peak.accumulateAndGet(count, Math::max);
            try { Thread.sleep(2); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            active.decrementAndGet(); return port == 80 ? TcpScanner.State.OPEN : TcpScanner.State.NO_RESPONSE;
        });
        List<TcpScanner.Result> results = bounded.scan(new ScanPlan("10.0.0.0/26", "80,81", 100), (result, count, total) -> completed.incrementAndGet());
        check(results.size() == 124 && completed.get() == 124, "Every check reported exactly once");
        check(peak.get() <= 32, "Concurrency bounded");
        check(results.get(0).host.equals("10.0.0.1") && results.get(0).port == 80, "Result ordering");
        check(results.stream().filter(r -> r.state == TcpScanner.State.NO_RESPONSE).count() == 62, "Silence retained independently of refusal");
        TcpScanner cancelled = new TcpScanner(); cancelled.cancel();
        check(cancelled.scan(new ScanPlan("10.0.0.1", "80", 100), (r,c,t) -> {}).isEmpty(), "Pre-cancellation opens no sockets");
        CountDownLatch entered = new CountDownLatch(1);
        TcpScanner running = new TcpScanner((host,port,timeout) -> {
            entered.countDown(); try { Thread.sleep(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            return TcpScanner.State.NO_RESPONSE;
        });
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<List<TcpScanner.Result>> task = executor.submit(() -> running.scan(new ScanPlan("10.0.0.0/24", "80", 100), (r,c,t) -> {}));
            check(entered.await(2, TimeUnit.SECONDS), "Scan started"); running.cancel();
            check(task.get(2, TimeUnit.SECONDS).isEmpty(), "Cancellation stops queued work and interrupts workers");
        } finally { executor.shutdownNow(); }
        check(ScanPlan.parsePorts(ScanPlan.COMPLETE_PORTS).size()>ScanPlan.parsePorts(ScanPlan.FAST_PORTS).size(),"Complete default expands ports");
        check(ScanPlan.Mode.COMPLETE.identificationSeconds>ScanPlan.Mode.FAST.identificationSeconds,"Complete identification budget");
        AtomicInteger calls=new AtomicInteger(); List<Integer> timeouts=Collections.synchronizedList(new ArrayList<>());
        TcpScanner retry=new TcpScanner((host,port,timeout) -> { timeouts.add(timeout); return calls.incrementAndGet()==1?TcpScanner.State.NO_RESPONSE:TcpScanner.State.OPEN; });
        TcpScanner.Result recovered=retry.scan(new ScanPlan("10.0.0.1","80",500,ScanPlan.Mode.COMPLETE),(r,c,t)->{}).get(0);
        check(recovered.state==TcpScanner.State.OPEN && recovered.attempts==2 && timeouts.equals(List.of(500,1000)),"Retry recovers a slow endpoint with longer timeout");
        TcpScanner silence=new TcpScanner((host,port,timeout)->TcpScanner.State.NO_RESPONSE);
        TcpScanner.Result silent=silence.scan(new ScanPlan("10.0.0.1","80",2500,ScanPlan.Mode.COMPLETE),(r,c,t)->{}).get(0);
        check(silent.attempts==2 && silent.timeoutMs==3000,"Retry timeout capped at 3000 ms");
        AtomicInteger refusalCalls=new AtomicInteger();
        TcpScanner refusal=new TcpScanner((host,port,timeout)-> { refusalCalls.incrementAndGet(); return TcpScanner.State.CLOSED; });
        check(refusal.scan(new ScanPlan("10.0.0.1","80",500,ScanPlan.Mode.COMPLETE),(r,c,t)->{}).get(0).attempts==1 && refusalCalls.get()==1,"Do not retry explicit refusal");
        TcpScanner errors=new TcpScanner((host,port,timeout)->TcpScanner.State.ERROR);
        check(errors.scan(new ScanPlan("10.0.0.1","80",500,ScanPlan.Mode.COMPLETE),(r,c,t)->{}).get(0).attempts==1,"Do not retry routing errors");
        check(silence.scan(new ScanPlan("10.0.0.1","80",500,ScanPlan.Mode.FAST),(r,c,t)->{}).get(0).attempts==1,"Fast mode retains single attempt");
        TcpScanner[] cancelBetween={null}; AtomicInteger cancelCalls=new AtomicInteger();
        cancelBetween[0]=new TcpScanner((host,port,timeout)-> { cancelCalls.incrementAndGet(); cancelBetween[0].cancel(); return TcpScanner.State.NO_RESPONSE; });
        check(cancelBetween[0].scan(new ScanPlan("10.0.0.1","80",500,ScanPlan.Mode.COMPLETE),(r,c,t)->{}).isEmpty() && cancelCalls.get()==1,"Cancellation suppresses retries and partial connection results");
        System.out.println("PASS: " + assertions + " assertions (validation, real sockets, concurrency, cancellation)");
    }
}
