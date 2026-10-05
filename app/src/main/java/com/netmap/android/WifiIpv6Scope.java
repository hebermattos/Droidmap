package com.netmap.android;

import android.content.Context;
import android.net.*;
import java.net.*;
import java.util.*;

/** Captures the Wi-Fi network matching the requested target; rejects off-link discoveries. */
final class WifiIpv6Scope {
    final Network network;
    final LinkProperties links;
    private WifiIpv6Scope(Network network,LinkProperties links) { this.network=network;this.links=links; }
    static WifiIpv6Scope capture(Context context,ScanPlan plan) {
        ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if(cm!=null) try {
            for(Network network:cm.getAllNetworks()) {
                NetworkCapabilities caps=cm.getNetworkCapabilities(network);
                LinkProperties links=cm.getLinkProperties(network);
                if(caps==null||links==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) continue;
                for(LinkAddress local:links.getLinkAddresses()) for(String host:plan.hosts)
                    if(WifiReverseDns.inSubnet(local,host)&&zoneMatches(host,links.getInterfaceName()))
                        return new WifiIpv6Scope(network,links);
            }
        } catch(SecurityException ignored) { }
        return new WifiIpv6Scope(null,null);
    }
    private static boolean zoneMatches(String host,String iface) {
        String suffix=IpAddresses.zoneSuffix(host);
        if(suffix.isEmpty()) return true;
        String zone=suffix.substring(1);
        if(zone.equals(iface)) return true;
        try { NetworkInterface nic=NetworkInterface.getByName(iface);return nic!=null&&zone.equals(Integer.toString(nic.getIndex())); }
        catch(Exception e) { return false; }
    }
    String normalize(String host) {
        if(links==null||!zoneMatches(host,links.getInterfaceName())) return null;
        try {
            InetAddress a=IpAddresses.literal(host);
            if(!(a instanceof Inet6Address)||a.isAnyLocalAddress()||a.isLoopbackAddress()||a.isMulticastAddress()) return null;
            if(!(a.isLinkLocalAddress()||a.isSiteLocalAddress()||ScanPlan.isUniqueLocal(a)||IpAddresses.global(a))) return null;
            boolean matching=a.isLinkLocalAddress();
            for(LinkAddress local:links.getLinkAddresses())
                if(IpAddresses.inPrefix(local.getAddress(),local.getPrefixLength(),a)) matching=true;
            if(!matching) return null;
            String raw=ScanPlan.stripZone(a.getHostAddress());
            if(a.isLinkLocalAddress()) {
                String iface=links.getInterfaceName();
                if(iface==null||iface.isEmpty()) return null;
                return raw+"%"+iface;
            }
            return raw;
        } catch(Exception e) { return null; }
    }
    boolean accepts(String host) { return normalize(host)!=null; }
    boolean owns(String host) {
        if(links==null) return false;
        for(LinkAddress local:links.getLinkAddresses()) if(IpAddresses.sameAddress(host,local.getAddress().getHostAddress())) return true;
        return false;
    }
}
