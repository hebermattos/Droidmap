package com.netmap.android;

import android.content.Context;
import android.net.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Collects IPv6 addresses already observable by Android; never enumerates an IPv6 prefix. */
final class Ipv6NeighborDiscovery {
    private static final int MAX=512;

    static Set<String> discover(Context context) {
        LinkedHashSet<String> found=new LinkedHashSet<>();
        addWifiAddresses(context,found);
        addIpNeighbors(found);
        return Collections.unmodifiableSet(found);
    }

    private static void addWifiAddresses(Context context,Set<String> found) {
        ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if(cm==null)return;
        try {
            for(Network network:cm.getAllNetworks()) {
                NetworkCapabilities caps=cm.getNetworkCapabilities(network);
                LinkProperties lp=cm.getLinkProperties(network);
                if(caps==null||lp==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))continue;
                String iface=lp.getInterfaceName();
                for(LinkAddress link:lp.getLinkAddresses()) {
                    InetAddress a=link.getAddress();
                    if(a instanceof Inet6Address && usable(a)) add(found,scoped(a,iface));
                }
            }
        } catch(SecurityException ignored) {}
    }

    private static void addIpNeighbors(Set<String> found) {
        Process p=null;
        try {
            p=new ProcessBuilder("/system/bin/ip","-6","neigh","show").redirectErrorStream(true).start();
            try(BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream(),StandardCharsets.UTF_8))) {
                String line;
                while(found.size()<MAX && (line=r.readLine())!=null) {
                    String[] parts=line.trim().split("\\s+");
                    if(parts.length<1)continue;
                    String candidate=parts[0],iface="";
                    for(int i=1;i+1<parts.length;i++)if("dev".equals(parts[i])){iface=parts[i+1];break;}
                    if(candidate.indexOf(':')<0)continue;
                    try {
                        InetAddress a=InetAddress.getByName(ScanPlan.stripZone(candidate));
                        if(a instanceof Inet6Address && usable(a)) add(found,a.isLinkLocalAddress()&&!iface.isEmpty()?ScanPlan.stripZone(a.getHostAddress())+"%"+iface:a.getHostAddress());
                    } catch(Exception ignored) {}
                }
            }
        } catch(Exception ignored) {
            // Android versions may deny access to the neighbor table; mDNS/NSD still discovers peers.
        } finally { if(p!=null)p.destroy(); }
    }

    private static boolean usable(InetAddress a) {
        return !a.isAnyLocalAddress()&&!a.isLoopbackAddress()&&!a.isMulticastAddress()&&
            (a.isLinkLocalAddress()||a.isSiteLocalAddress()||ScanPlan.isUniqueLocal(a)||isGlobal(a));
    }
    private static boolean isGlobal(InetAddress a) { byte[] b=a.getAddress();return b.length==16&&(b[0]&0xe0)==0x20; }
    private static String scoped(InetAddress a,String iface) {
        String raw=ScanPlan.stripZone(a.getHostAddress());
        return a.isLinkLocalAddress()&&iface!=null&&!iface.isEmpty()?raw+"%"+iface:raw;
    }
    private static void add(Set<String> found,String value) { if(found.size()<MAX)found.add(value); }
}