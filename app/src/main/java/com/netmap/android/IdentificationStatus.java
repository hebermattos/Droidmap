package com.netmap.android;

/** Stable values at the evidence and JSON boundaries. */
enum IdentificationStatus {
    COMPLETED("completed"),
    PARTIAL("partial"),
    CANCELLED("cancelled");

    final String wireValue;

    IdentificationStatus(String wireValue) {
        this.wireValue = wireValue;
    }

    static IdentificationStatus of(boolean cancelled, boolean partial) {
        if (cancelled) return CANCELLED;
        return partial ? PARTIAL : COMPLETED;
    }
}
