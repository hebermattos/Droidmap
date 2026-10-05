package com.netmap.android;

import java.net.*;
import java.util.*;

/** Literal private IPv4 networks or single local IPv6 targets; caps work before sockets open. */
public final class ScanPlan {
    public enum Mode {
        FAST(0,20,6,4), COMPLETE(1,60,12,8);
        public final int retries,identificationSeconds,discoverySeconds,fingerprintLimit;
        Mode(int retries,int identificationSeconds,int discoverySeconds,int fingerprintLimit){this.retries=retries;this.identificationSeconds=identificationSeconds;this.discoverySeconds=discoverySeconds;this.fingerprintLimit=fingerprintLimit;}
        public int nextTimeout(int timeout){return Math.min(3000,timeout*2);}
    }
    public static final String FAST_PORTS="21,22,23,53,80,139,443,445,554,1080,1883,3389,5060,8000,8009,8080,8443,8888,9100";
    public static final String COMPLETE_PORTS=FAST_PORTS+",81,135,389,515,631,989,990,1433,1521,3306,5432,5900,5985,5986,8001,8081,8090,9000,9090,10000";
    public final Mode mode; public final List<String> hosts; public final List<Integer> ports; public final int timeoutMs; public final boolean adaptive;
    public ScanPlan(String target,String portText,int timeoutMs){this(target,portText,timeoutMs,Mode.FAST);}
    public ScanPlan(String target,String portText,int timeoutMs,Mode mode){this(target,portText,timeoutMs,mode,false);}
    public ScanPlan(String target,String portText,int timeoutMs,Mode mode,boolean adaptive){
        this.adaptive=adaptive;this.mode=Objects.requireNonNull(mode);hosts=parseHosts(target);ports=parsePorts(portText);
        if(timeoutMs<100||timeoutMs>3000) throw new IllegalArgumentException("Timeout must be 100–3000 ms.");this.timeoutMs=timeoutMs;
    }
    public static List<String> parseHosts(String input){
        String value=input==null?"":input.trim();
        if(value.indexOf(':')>=0) return Collections.singletonList(parseIpv6(value));
        String[] parts=value.split("/",-1);
        if(parts.length>2) throw new IllegalArgumentException("Enter a private IPv4 address/network or a local IPv6 address.");
        long address=ipv4(parts[0]); int prefix=parts.length==1?32:number(parts[1]);
        if(prefix<24||prefix>32) throw new IllegalArgumentException("IPv4 network prefix must be /24–/32 (at most 256 addresses).");
        long mask=(0xffffffffL<<(32-prefix))&0xffffffffL,first=address&mask,last=first|(~mask&0xffffffffL);
        if(!isPrivate(first)||!isPrivate(last)) throw new IllegalArgumentException("Use a private IPv4 network or a local IPv6 address.");
        if(prefix<=30){first++;last--;} List<String> hosts=new ArrayList<>();for(long ip=first;ip<=last;ip++)hosts.add(format(ip));
        return Collections.unmodifiableList(hosts);
    }
    static String parseIpv6(String text){
        if(text.contains("/")) throw new IllegalArgumentException("IPv6 subnet sweeps are not supported; select a discovered IPv6 host.");
        String address=text,zone=""; int percent=text.indexOf('%');
        if(percent>=0){address=text.substring(0,percent);zone=text.substring(percent+1);if(!zone.matches("[A-Za-z0-9_.-]{1,32}"))throw new IllegalArgumentException("Invalid IPv6 interface scope.");}
        try{
            InetAddress parsed=InetAddress.getByName(address);
            if(!(parsed instanceof Inet6Address)) throw new IllegalArgumentException("Enter a literal IPv6 address.");
            if(!(parsed.isLinkLocalAddress()||parsed.isSiteLocalAddress()||isUniqueLocal(parsed)||IpAddresses.global(parsed))) throw new IllegalArgumentException("Use a unicast IPv6 address on the connected Wi-Fi network.");
            return parsed.getHostAddress().split("%",2)[0]+(zone.isEmpty()?"":"%"+zone);
        }catch(UnknownHostException e){throw new IllegalArgumentException("Invalid IPv6 address.");}
    }
    static boolean isIpv6(String host){return host.indexOf(':')>=0;}
    static boolean isUniqueLocal(InetAddress address){byte[] b=address.getAddress();return b.length==16&&(b[0]&0xfe)==0xfc;}
    static int compareHosts(String a,String b){
        try{byte[] x=InetAddress.getByName(stripZone(a)).getAddress(),y=InetAddress.getByName(stripZone(b)).getAddress();if(x.length!=y.length)return Integer.compare(x.length,y.length);for(int i=0;i<x.length;i++){int c=Integer.compare(x[i]&255,y[i]&255);if(c!=0)return c;}return a.compareTo(b);}catch(Exception e){return a.compareTo(b);}
    }
    static String stripZone(String host){int p=host.indexOf('%');return p<0?host:host.substring(0,p);}
    static long ipv4(String text){String[] octets=text.split("\\.",-1);if(octets.length!=4)throw new IllegalArgumentException("Enter a literal IPv4 address.");long result=0;for(String octet:octets){int value=number(octet);if(value>255||octet.length()>3)throw new IllegalArgumentException("Invalid IPv4 address.");result=(result<<8)|value;}return result;}
    private static boolean isPrivate(long ip){return(ip>>>24)==10||(ip>>>20)==0xac1||(ip>>>16)==0xc0a8;}
    private static String format(long ip){return(ip>>>24)+"."+((ip>>>16)&255)+"."+((ip>>>8)&255)+"."+(ip&255);}
    private static int number(String value){if(!value.matches("[0-9]{1,5}"))throw new IllegalArgumentException("Invalid numeric value: "+value);return Integer.parseInt(value);}
    public static List<Integer> parsePorts(String text){TreeSet<Integer> ports=new TreeSet<>();for(String token:text.split(",",-1)){String[] range=token.trim().split("-",-1);if(range.length>2)throw new IllegalArgumentException("Use ports such as 22,80,443,8000-8010.");int start=number(range[0].trim()),end=range.length==2?number(range[1].trim()):start;if(start<1||end>65535||end<start||end-start>=256)throw new IllegalArgumentException("Use 1–65535 and at most 256 distinct ports.");for(int p=start;p<=end;p++)ports.add(p);if(ports.size()>256)throw new IllegalArgumentException("Select at most 256 distinct ports.");}return Collections.unmodifiableList(new ArrayList<>(ports));}
}