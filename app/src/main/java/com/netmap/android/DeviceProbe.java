package com.netmap.android;

/** A bounded, read-only protocol probe. Routing order is owned by DeviceIdentifier. */
interface DeviceProbe {
    boolean supports(int port, String serviceType);

    void probe(String host, int port, String serviceType);
}
