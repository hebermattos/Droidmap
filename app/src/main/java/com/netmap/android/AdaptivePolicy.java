package com.netmap.android;

import java.util.function.BooleanSupplier;

/** Conservative feedback: never shorten the entered timeout or skip selected ports. */
final class AdaptivePolicy {
    private final int baseline; private int limit=16,inFlight,samples,silent; private long latency;
    private double responseMs;
    AdaptivePolicy(int baseline) { this.baseline=baseline; }
    synchronized boolean enter(BooleanSupplier cancelled) throws InterruptedException {
        while(inFlight>=limit && !cancelled.getAsBoolean()) wait(25);
        if(cancelled.getAsBoolean()) return false; inFlight++; return true;
    }
    synchronized void leave() {inFlight--;notifyAll();}
    synchronized void observe(TcpScanner.State state,long elapsedMs) {
        samples++; if(state==TcpScanner.State.NO_RESPONSE) silent++;
        if(state==TcpScanner.State.OPEN || state==TcpScanner.State.CLOSED) {
            responseMs=responseMs==0?elapsedMs:responseMs*0.8+elapsedMs*0.2; latency+=elapsedMs;
        }
        if(samples>=32) {
            if(silent>=16) limit=Math.max(4,limit/2);
            else if(silent<=3 && latency<samples*(long)baseline/2) limit=Math.min(32,limit+4);
            samples=0; silent=0; latency=0; notifyAll();
        }
    }
    synchronized int timeout() { return Math.max(baseline,(int)Math.min(3000,Math.ceil(responseMs*4))); }
    synchronized int concurrency() {return limit;}
}
