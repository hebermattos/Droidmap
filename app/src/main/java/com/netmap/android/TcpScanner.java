package com.netmap.android;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** TCP connect scanning without raw sockets. One instance per scan. */
public final class TcpScanner {
    interface Connector { State connect(String host, int port, int timeout); }
    private final Connector connector;
    public TcpScanner() { connector = this::probe; }
    TcpScanner(Connector connector) { this.connector = connector; }
    public enum State { OPEN, CLOSED, NO_RESPONSE, ERROR }
    public static final class Result {
        public final String host;
        public final int port;
        public final State state;
        public final int attempts, timeoutMs;
        public Result(String host, int port, State state) { this(host,port,state,1,0); }
        public Result(String host,int port,State state,int attempts,int timeoutMs) {
            this.host=host; this.port=port; this.state=state; this.attempts=attempts; this.timeoutMs=timeoutMs;
        }
    }
    public interface Listener { void onResult(Result result, int completed, int total); }
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private final Set<Socket> active = ConcurrentHashMap.newKeySet();
    public void cancel() {
        cancelled.set(true);
        for (Socket socket : active) try { socket.close(); } catch (IOException ignored) { }
    }
    public boolean isCancelled() { return cancelled.get(); }
    public List<Result> scan(ScanPlan plan, Listener listener) throws InterruptedException {
        ExecutorService workers = Executors.newFixedThreadPool(32);
        List<Result> results = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger complete = new AtomicInteger();
        int total = plan.hosts.size() * plan.ports.size();
        try {
            AdaptivePolicy policy=plan.adaptive?new AdaptivePolicy(plan.timeoutMs):null;
            Set<String> responding=ConcurrentHashMap.newKeySet();
            int seed=plan.ports.contains(80)?80:plan.ports.contains(443)?443:plan.ports.get(0);
            if(plan.adaptive) {
                List<java.util.concurrent.Future<?>> first=new ArrayList<>();
                for(String host:plan.hosts) first.add(workers.submit(()->task(plan,host,seed,policy,responding,results,complete,total,listener)));
                for(java.util.concurrent.Future<?> future:first) try { future.get(); } catch(java.util.concurrent.ExecutionException e) { throw new IllegalStateException("Probe failed",e.getCause()); }
            }
            List<String> ordered=new ArrayList<>(plan.hosts);
            if(plan.adaptive) ordered.sort((a,b)->Boolean.compare(responding.contains(b),responding.contains(a)));
            for(String host:ordered) for(int port:plan.ports) {
                if(cancelled.get()) break;
                if(plan.adaptive && port==seed) continue;
                workers.submit(()->task(plan,host,port,policy,responding,results,complete,total,listener));
            }
            workers.shutdown();
            while (!workers.awaitTermination(100, TimeUnit.MILLISECONDS)) {
                if (cancelled.get()) { workers.shutdownNow(); cancel(); }
            }
        } catch (InterruptedException e) {
            cancel();
            throw e;
        } finally {
            workers.shutdownNow();
            for (Socket socket : active) try { socket.close(); } catch (IOException ignored) { }
        }
        List<Result> snapshot = new ArrayList<>(results);
        snapshot.sort((a, b) -> {
            int hostOrder = Long.compare(ScanPlan.ipv4(a.host), ScanPlan.ipv4(b.host));
            return hostOrder != 0 ? hostOrder : Integer.compare(a.port, b.port);
        });
        return snapshot;
    }
    private void task(ScanPlan plan,String host,int port,AdaptivePolicy policy,Set<String> responding,List<Result> results,AtomicInteger complete,int total,Listener listener) {
        if(cancelled.get()) return; boolean entered=false;
        try {
            if(policy!=null) { entered=policy.enter(cancelled::get); if(!entered) return; }
            long start=System.nanoTime();
            Result result=inspect(host,port,policy==null?plan.timeoutMs:policy.timeout(),plan.mode);
            if(policy!=null) policy.observe(result.state,TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start));
            if(cancelled.get()) return;
            if(result.state==State.OPEN || result.state==State.CLOSED) responding.add(host);
            results.add(result); listener.onResult(result,complete.incrementAndGet(),total);
        } catch(InterruptedException e) {Thread.currentThread().interrupt();}
        finally {if(entered) policy.leave();}
    }
    Result inspect(String host,int port,int timeout,ScanPlan.Mode mode) {
        int attempts=0; State state=State.ERROR;
        for(int retry=0;retry<=mode.retries;retry++) {
            if(cancelled.get() || Thread.currentThread().isInterrupted()) break;
            attempts++; state=connector.connect(host,port,timeout);
            if(state!=State.NO_RESPONSE || retry==mode.retries) break;
            timeout=mode.nextTimeout(timeout);
        }
        return new Result(host,port,state,attempts,timeout);
    }
    State probe(String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            active.add(socket);
            try {
                if (cancelled.get()) return State.ERROR;
                socket.connect(new InetSocketAddress(host, port), timeout);
                return State.OPEN;
            } finally { active.remove(socket); }
        } catch (SocketTimeoutException e) { return State.NO_RESPONSE;
        } catch (ConnectException e) {
            // Only explicit refusal is evidence of a closed port/responding device.
            String message = e.getMessage();
            return message != null && message.toLowerCase(java.util.Locale.ROOT).contains("refused") ? State.CLOSED : State.ERROR;
        } catch (IOException | SecurityException e) { return State.ERROR; }
    }
}
