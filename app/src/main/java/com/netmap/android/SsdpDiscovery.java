package com.netmap.android;

import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Bounded SSDP collection; only same-sender UPnP locations are retained. */
final class SsdpDiscovery {
    static final class Result {
        final Map<String, String> locations;
        final String failure;

        Result(Map<String, String> locations, String failure) {
            this.locations = locations;
            this.failure = failure;
        }
    }

    private final ProbeContext context;
    private final Set<String> hosts;

    SsdpDiscovery(ProbeContext context, Set<String> hosts) {
        this.context = context;
        this.hosts = hosts;
    }

    Result discover() {
        String failure = "";
        Map<String, String> locations = new LinkedHashMap<>();
        try (DatagramSocket socket = new DatagramSocket()) {
            context.track(socket);
            try {
                socket.setSoTimeout(200);
                byte[] request =
                        ("M-SEARCH * HTTP/1.1\r\n"
                                        + "HOST: 239.255.255.250:1900\r\n"
                                        + "MAN: \"ssdp:discover\"\r\n"
                                        + "MX: 1\r\n"
                                        + "ST: ssdp:all\r\n\r\n")
                                .getBytes(StandardCharsets.US_ASCII);
                socket.send(
                        new DatagramPacket(
                                request,
                                request.length,
                                InetAddress.getByName("239.255.255.250"),
                                1900));
                long end =
                        System.nanoTime()
                                + TimeUnit.SECONDS.toNanos(
                                        context.plan.mode == ScanPlan.Mode.COMPLETE ? 5 : 3);
                int packets = 0;
                while (!context.stopped() && System.nanoTime() < end && packets < 512) {
                    byte[] buffer = new byte[8192];
                    DatagramPacket response = new DatagramPacket(buffer, buffer.length);
                    try {
                        socket.receive(response);
                    } catch (SocketTimeoutException ignored) {
                        continue;
                    }
                    packets++;
                    String ip = response.getAddress().getHostAddress();
                    if (!hosts.contains(ip)) continue;
                    String raw =
                            new String(buffer, 0, response.getLength(), StandardCharsets.UTF_8);
                    if (!raw.startsWith("HTTP/1.1 200") && !raw.startsWith("HTTP/1.0 200"))
                        continue;
                    Map<String, String> h = DeviceEvidence.headers(raw);
                    for (String key : new String[] {"server", "st", "usn"})
                        context.evidence.add(
                                ip, "SSDP", key.equals("st") ? "serviceType" : key, h.get(key));
                    String location = h.get("location");
                    if (UpnpProbe.allowedLocation(location, ip)) {
                        locations.putIfAbsent(ip, location);
                        try {
                            URI uri = new URI(location);
                            context.evidence.advertise(
                                    ip,
                                    "SSDP description",
                                    "_http._tcp.",
                                    uri.getPort() == -1 ? 80 : uri.getPort());
                        } catch (URISyntaxException ignored) {
                        }
                    }
                }
            } finally {
                context.untrack(socket);
            }
        } catch (IOException | SecurityException e) {
            failure = e.getClass().getSimpleName();
        }
        // Description fetches use the same fixed pool and global budget as fingerprints.
        return new Result(locations, failure);
    }
}
