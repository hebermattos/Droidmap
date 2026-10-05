package com.netmap.android;

import java.net.*;
import java.util.*;

/** Literal address utilities; interface zones never enter DNS names or HTTP authorities. */
final class IpAddresses {
    static InetAddress literal(String host) throws UnknownHostException {
        String raw=ScanPlan.stripZone(host);
        if(raw.indexOf(':')<0) { ScanPlan.ipv4(raw); }
        else if(!raw.matches("[0-9a-fA-F:.]+")) throw new UnknownHostException("Not a literal address");
        return InetAddress.getByName(raw);
    }
    static String canonical(String host) {
        try { return ScanPlan.stripZone(literal(host).getHostAddress())+zoneSuffix(host); }
        catch(Exception e) { return host; }
    }
    static String zoneSuffix(String host) { int p=host.indexOf('%'); return p<0?"":host.substring(p); }
    static boolean sameAddress(String a,String b) {
        try { return Arrays.equals(literal(a).getAddress(),literal(b).getAddress()); }
        catch(Exception e) { return false; }
    }
    static boolean global(InetAddress a) { byte[] b=a.getAddress();return b.length==16&&(b[0]&0xe0)==0x20; }
    static String kind(InetAddress a) {
        if(a.isLinkLocalAddress()) return "Link-local";
        if(ScanPlan.isUniqueLocal(a)) return "Unique-local";
        if(a.isSiteLocalAddress()) return "Site-local (deprecated)";
        return "Global unicast on local Wi-Fi";
    }
    static String authority(String host,int port) {
        String raw=ScanPlan.stripZone(host);
        return (ScanPlan.isIpv6(raw)?"["+raw+"]":raw)+":"+port;
    }
    static boolean inPrefix(InetAddress local,int prefix,InetAddress remote) {
        byte[] a=local.getAddress(),b=remote.getAddress();
        if(a.length!=b.length||prefix<0||prefix>a.length*8) return false;
        for(int i=0;i<a.length;i++) {
            int bits=Math.max(0,Math.min(8,prefix-i*8));
            int mask=bits==0?0:(255<<(8-bits))&255;
            if((a[i]&mask)!=(b[i]&mask)) return false;
        }
        return true;
    }
}
