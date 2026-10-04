package com.netmap.android;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.json.*;

public class PerformanceTest {
    @Test public void silenceRetainsConcurrencyAndTimeoutFloor() {
        AdaptivePolicy policy=new AdaptivePolicy(200);
        for(int i=0;i<320;i++) policy.observe(TcpScanner.State.NO_RESPONSE,200);
        assertEquals(32,policy.concurrency()); assertEquals(200,policy.timeout());
    }
    @Test public void errorsBackOffAndQuickResponsesRecover() {
        AdaptivePolicy policy=new AdaptivePolicy(200);
        for(int i=0;i<96;i++) policy.observe(TcpScanner.State.ERROR,1);
        assertEquals(8,policy.concurrency());
        for(int i=0;i<96;i++) policy.observe(TcpScanner.State.CLOSED,5);
        assertEquals(32,policy.concurrency()); assertEquals(200,policy.timeout());
    }
    @Test public void slowConfirmedResponsesBackOffWithinBounds() {
        AdaptivePolicy policy=new AdaptivePolicy(200);
        for(int i=0;i<128;i++) policy.observe(TcpScanner.State.OPEN,180);
        assertEquals(8,policy.concurrency()); assertTrue(policy.timeout()>=200); assertTrue(policy.timeout()<=3000);
        policy.observe(TcpScanner.State.OPEN,10000); assertEquals(3000,policy.timeout());
    }
    @Test public void silentAdaptiveScanUsesAvailableWorkersWithoutDroppingChecks() throws Exception {
        CountDownLatch simultaneous=new CountDownLatch(24); AtomicInteger active=new AtomicInteger(),maximum=new AtomicInteger();
        TcpScanner scanner=new TcpScanner((host,port,timeout) -> {
            int n=active.incrementAndGet(); maximum.accumulateAndGet(n,Math::max); simultaneous.countDown();
            try {simultaneous.await(2,TimeUnit.SECONDS);} catch(InterruptedException e) {Thread.currentThread().interrupt();}
            finally {active.decrementAndGet();}
            return TcpScanner.State.NO_RESPONSE;
        });
        ScanPlan plan=new ScanPlan("192.168.1.0/27","80",200,ScanPlan.Mode.FAST,true);
        List<TcpScanner.Result> results=scanner.scan(plan,(r,c,t)->{});
        assertEquals(plan.hosts.size(),results.size()); assertTrue(maximum.get()>=24); assertTrue(maximum.get()<=32);
        for(TcpScanner.Result result:results) {assertEquals(200,result.timeoutMs); assertEquals(1,result.attempts);}
    }
    private DeviceIdentifier identifier(Runnable task) {
        ScanPlan plan=new ScanPlan("192.168.1.1","80",200);
        return new DeviceIdentifier(plan,new DeviceEvidence(plan.hosts),null,task);
    }
    @Test public void discoveryStartsAsynchronouslyAndIsReused() throws Exception {
        CountDownLatch began=new CountDownLatch(1),release=new CountDownLatch(1); AtomicInteger runs=new AtomicInteger();
        DeviceIdentifier identifier=identifier(() -> {runs.incrementAndGet(); began.countDown(); try {release.await();} catch(InterruptedException e) {Thread.currentThread().interrupt();}});
        try {
            identifier.startDiscovery(); assertTrue(began.await(1,TimeUnit.SECONDS));
            identifier.startDiscovery(); assertEquals(1,runs.get());
            // TCP work can proceed while SSDP is blocked, then identification joins the same task.
            assertEquals(1,release.getCount()); release.countDown();
            assertTrue(identifier.awaitDiscovery(System.nanoTime()+TimeUnit.SECONDS.toNanos(1))); assertEquals(1,runs.get());
        } finally {release.countDown(); identifier.cancel();}
    }
    @Test public void cancellationInterruptsDiscoveryAndDoesNotStartAnotherTask() throws Exception {
        CountDownLatch began=new CountDownLatch(1),exited=new CountDownLatch(1); AtomicInteger runs=new AtomicInteger();
        DeviceIdentifier identifier=identifier(() -> {runs.incrementAndGet(); began.countDown(); try {new CountDownLatch(1).await();} catch(InterruptedException e) {Thread.currentThread().interrupt();} finally {exited.countDown();}});
        identifier.startDiscovery(); assertTrue(began.await(1,TimeUnit.SECONDS)); identifier.cancel();
        assertTrue(exited.await(1,TimeUnit.SECONDS)); assertFalse(identifier.awaitDiscovery(System.nanoTime()+TimeUnit.SECONDS.toNanos(1))); assertEquals(1,runs.get());
    }
    @Test public void discoveryJoinRespectsIdentificationBudget() throws Exception {
        CountDownLatch began=new CountDownLatch(1),exited=new CountDownLatch(1);
        DeviceIdentifier identifier=identifier(() -> {began.countDown(); try {new CountDownLatch(1).await();} catch(InterruptedException e) {Thread.currentThread().interrupt();} finally {exited.countDown();}});
        try {
            identifier.startDiscovery(); assertTrue(began.await(1,TimeUnit.SECONDS)); assertFalse(identifier.awaitDiscovery(System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(100)));
            assertTrue(identifier.isTimedOut()); assertTrue(exited.await(1,TimeUnit.SECONDS));
        } finally {identifier.cancel();}
    }
    @Test public void respondersAndAnnouncementsPrecedeSilentHostsWithoutOmittingThem() {
        ScanPlan plan=new ScanPlan("192.168.1.0/29","80",200); DeviceEvidence evidence=new DeviceEvidence(plan.hosts);
        evidence.add("192.168.1.4","mDNS","serviceName","Printer"); DeviceIdentifier identifier=new DeviceIdentifier(plan,evidence);
        List<TcpScanner.Result> checks=Arrays.asList(new TcpScanner.Result("192.168.1.6",80,TcpScanner.State.CLOSED),new TcpScanner.Result("192.168.1.3",80,TcpScanner.State.OPEN));
        List<String> order=identifier.identificationOrder(checks);
        assertEquals(Arrays.asList("192.168.1.3","192.168.1.4","192.168.1.6"),order.subList(0,3));
        assertEquals(new HashSet<>(plan.hosts),new HashSet<>(order)); assertEquals(plan.hosts.size(),order.size()); identifier.cancel();
    }
    @Test public void previewContainsOnlyObservedDevicesAndConfirmedOpenPorts() throws Exception {
        Map<String,List<DeviceEvidence.Observation>> evidence=new LinkedHashMap<>();
        evidence.put("192.168.1.4",Collections.singletonList(new DeviceEvidence.Observation("mDNS","friendlyName","Printer")));
        List<TcpScanner.Result> checks=Arrays.asList(new TcpScanner.Result("192.168.1.1",80,TcpScanner.State.NO_RESPONSE),new TcpScanner.Result("192.168.1.2",80,TcpScanner.State.CLOSED),new TcpScanner.Result("192.168.1.3",80,TcpScanner.State.OPEN));
        JSONObject preview=new JSONObject(ScanReport.preview("192.168.1.0/24",checks,Arrays.asList(new TcpScanner.Result("192.168.1.4",8080,TcpScanner.State.OPEN)),evidence));
        assertTrue(preview.getBoolean("partial")); assertEquals(3,preview.getJSONArray("devices").length()); assertEquals(2,preview.getJSONArray("checks").length());
        assertEquals("Printer",preview.getJSONArray("devices").getJSONObject(0).getString("reportedName"));
        for(int i=0;i<preview.getJSONArray("checks").length();i++) assertEquals("OPEN",preview.getJSONArray("checks").getJSONObject(i).getString("state"));
    }
}
