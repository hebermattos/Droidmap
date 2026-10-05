package com.netmap.android;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Map;

/** Bounded NetBios metadata lookup. */
final class NetBiosProbe {
    private final ProbeContext context;

    NetBiosProbe(ProbeContext context) {
        this.context = context;
    }

    void netbios(String host) {
        if (context.stopped() || ScanPlan.isIpv6(host)) return;
        int id = java.util.concurrent.ThreadLocalRandom.current().nextInt(65536);
        try (DatagramSocket socket = new DatagramSocket()) {
            context.track(socket);
            try {
                if (context.stopped()) return;
                socket.connect(InetAddress.getByName(host), 137);
                socket.setSoTimeout(250);
                byte[] request = NetBios.query(id);
                socket.send(new DatagramPacket(request, request.length));
                byte[] buffer = new byte[4096];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                if (context.stopped()) return;
                Map<String, String> fields =
                        NetBios.parse(Arrays.copyOf(buffer, packet.getLength()), id);
                for (Map.Entry<String, String> field : fields.entrySet())
                    context.evidence.add(
                            host, "NetBIOS node status", field.getKey(), field.getValue());
            } finally {
                context.untrack(socket);
            }
        } catch (IOException | SecurityException ignored) {
        }
    }
}
