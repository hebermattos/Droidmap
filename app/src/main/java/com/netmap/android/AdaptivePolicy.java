package com.netmap.android;

import java.util.function.BooleanSupplier;

/** Silence alone is not congestion; retain coverage and the user's timeout floor. */
final class AdaptivePolicy {
    private final int baseline;
    private int limit=32,inFlight,samples,responses,errors;
    private long latency;
    private double responseMs;
    AdaptivePolicy(int baseline) { this.baseline=baseline; }
    synchronized boolean enter(BooleanSupplier cancelled) throws InterruptedException {
        while(inFlight>=limit && !cancelled.getAsBoolean()) wait(25);
        if(cancelled.getAsBoolean()) return false; inFlight++; return true;
    }
    synchronized void leave() {inFlight--;notifyAll();}
    synchronized void observe(TcpScanner.State state,long elapsedMs) {
        samples++;
        if(state==TcpScanner.State.ERROR) errors++;
        if(state==TcpScanner.State.OPEN || state==TcpScanner.State.CLOSED) {
            responses++; latency+=elapsedMs;
            responseMs=responseMs==0?elapsedMs:responseMs*0.8+elapsedMs*0.2;
        }
        if(samples>=32) {
            if(errors>=8) limit=Math.max(8,limit/2);
            else if(responses>=8 && latency>responses*(long)baseline*3/4) limit=Math.max(8,limit-8);
            else if(responses>=4 && latency<responses*(long)baseline/2) limit=Math.min(32,limit+8);
            samples=0; responses=0; errors=0; latency=0; notifyAll();
        }
    }
    synchronized int timeout() { return Math.max(baseline,(int)Math.min(3000,Math.ceil(responseMs*4))); }
    synchronized int concurrency() {return limit;}
}
