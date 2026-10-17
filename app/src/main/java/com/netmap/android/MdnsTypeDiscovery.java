package com.netmap.android;

import android.net.LinkAddress;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.xbill.DNS.Message;

/** One-shot Wi-Fi multicast queries with legacy unicast replies; no port 5353 ownership. */
final class MdnsTypeDiscovery {
    private final WifiIpv6Scope wifi;
    private final Set<DatagramSocket> active = ConcurrentHashMap.newKeySet();
    private volatile boolean stopped;

    MdnsTypeDiscovery(WifiIpv6Scope wifi) { this.wifi = wifi; }

    void discover(Consumer<String> found, Consumer<String> notice) {
        if (wifi.network == null || wifi.links == null) return;
        Set<Boolean> families = new HashSet<>();
        for (LinkAddress link : wifi.links.getLinkAddresses()) {
            InetAddress local = link.getAddress();
            boolean ipv6 = local instanceof Inet6Address;
            if (stopped || local.isLoopbackAddress() || !families.add(ipv6)) continue;
            try {
                NetworkInterface nic = NetworkInterface.getByName(wifi.links.getInterfaceName());
                if (nic == null) continue;
                InetAddress group = ipv6
                        ? Inet6Address.getByAddress(null, InetAddress.getByName("ff02::fb").getAddress(), nic)
                        : InetAddress.getByName("224.0.0.251");
                browse(local, group, nic, found);
            } catch (IOException | RuntimeException error) {
                if (!stopped) notice.accept("mDNS service-type enumeration unavailable over "
                        + (ipv6 ? "IPv6" : "IPv4") + "; standard service discovery remains active.");
            }
        }
    }

    private void browse(InetAddress local, InetAddress group, NetworkInterface nic,
                        Consumer<String> found) throws IOException {
        try (MulticastSocket socket = new MulticastSocket(null)) {
            active.add(socket);
            try {
                if (stopped) return;
                socket.bind(new InetSocketAddress(local, 0));
                wifi.network.bindSocket(socket);
                socket.setNetworkInterface(nic);
                socket.setTimeToLive(255);
                socket.setSoTimeout(100);
                Message query = MdnsServiceTypes.query();
                byte[] request = query.toWire();
                socket.send(new DatagramPacket(request, request.length, group, 5353));
                long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(1000);
                Set<String> seen = new HashSet<>();
                byte[] buffer = new byte[4097];
                for (int packets = 0; packets < 128 && !stopped && System.nanoTime() < deadline;) {
                    DatagramPacket reply = new DatagramPacket(buffer, buffer.length);
                    try { socket.receive(reply); }
                    catch (SocketTimeoutException timeout) { continue; }
                    packets++;
                    if (reply.getPort() != 5353 || !onLink(reply.getAddress())) continue;
                    try {
                        for (String type : MdnsServiceTypes.parse(Arrays.copyOf(buffer, reply.getLength()), query)) {
                            if (seen.add(type)) found.accept(type);
                            if (seen.size() >= MdnsServiceTypes.MAX_TYPES) return;
                        }
                    } catch (IOException malformed) { /* Ignore malformed peer packets. */ }
                }
            } finally { active.remove(socket); }
        }
    }

    private boolean onLink(InetAddress address) {
        if (address instanceof Inet6Address) return wifi.accepts(address.getHostAddress());
        for (LinkAddress local : wifi.links.getLinkAddresses())
            if (IpAddresses.inPrefix(local.getAddress(), local.getPrefixLength(), address)) return true;
        return false;
    }

    void stop() {
        stopped = true;
        for (DatagramSocket socket : active) socket.close();
    }
}
