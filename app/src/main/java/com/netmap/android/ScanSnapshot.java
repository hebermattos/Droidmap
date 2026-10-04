package com.netmap.android;

/** Immutable state shared by the service and any visible activity. */
final class ScanSnapshot {
    final long runId;
    final boolean running, cancellable;
    final int done, total;
    final String target, message, report, text;
    ScanSnapshot(long runId, boolean running, boolean cancellable, int done, int total,
                 String target, String message, String report, String text) {
        this.runId=runId; this.running=running; this.cancellable=cancellable; this.done=done; this.total=total;
        this.target=target; this.message=message; this.report=report; this.text=text;
    }
    static ScanSnapshot ready() { return new ScanSnapshot(0,false,false,0,0,"","Ready","",""); }
}
