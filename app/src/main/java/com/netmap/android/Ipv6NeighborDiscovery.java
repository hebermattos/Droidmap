package com.netmap.android;

import android.net.LinkAddress;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;

/** Best-effort Wi-Fi observations; a cached neighbor entry does not prove current reachability. */
final class Ipv6NeighborDiscovery {
    static List<String> collect(WifiIpv6Scope wifi,DeviceEvidence evidence,BooleanSupplier cancelled) {
        List<String> notices=new ArrayList<>();
        if(wifi.links==null) {
            notices.add("IPv6 discovery skipped: no matching Wi-Fi network.");return notices;
        }
        for(LinkAddress local:wifi.links.getLinkAddresses()) {
            if(cancelled.getAsBoolean()) return notices;
            String ip=wifi.normalize(local.getAddress().getHostAddress());
            if(ip==null||!evidence.allowDiscoveredHost(ip)) continue;
            metadata(ip,wifi,evidence,"IPv6 local");
            evidence.add(ip,"IPv6 local","addressOrigin","This phone");
            evidence.add(ip,"IPv6 local","prefixLength",Integer.toString(local.getPrefixLength()));
        }
        Process process=null;ExecutorService reader=Executors.newSingleThreadExecutor();
        try {
            if(cancelled.getAsBoolean()) return notices;
            process=new ProcessBuilder("/system/bin/ip","-6","neigh","show","dev",wifi.links.getInterfaceName()).redirectErrorStream(true).start();
            Process command=process;
            Future<String> output=reader.submit(()->NmapRunner.readBounded(command.getInputStream(),65536));
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(1);
            while(!process.waitFor(50,TimeUnit.MILLISECONDS)) {
                if(cancelled.getAsBoolean()||System.nanoTime()>=deadline) throw new IOException("neighbor read interrupted or timed out");
            }
            String text=output.get(200,TimeUnit.MILLISECONDS);
            if(process.exitValue()!=0) throw new IOException("neighbor table access unavailable");
            int count=0;
            for(String line:text.split("\n")) {
                if(cancelled.getAsBoolean()||count++>=512) break;
                recordLine(line,wifi,evidence);
            }
        } catch(InterruptedException e) {Thread.currentThread().interrupt();}
        catch(Exception e) { if(!cancelled.getAsBoolean()) notices.add("IPv6 neighbor table unavailable; mDNS discovery remains active."); }
        finally {
            if(process!=null) {process.destroyForcibly();try {process.getInputStream().close();}catch(IOException ignored) {}}
            reader.shutdownNow();
        }
        return notices;
    }
    static void recordLine(String line,WifiIpv6Scope wifi,DeviceEvidence evidence) {
        String[] parts=line.trim().split("\\s+");
        if(parts.length<1||parts[0].indexOf(':')<0) return;
        String iface=wifi.links.getInterfaceName(),mac="",state=parts[parts.length-1];
        for(int i=1;i+1<parts.length;i++) {
            if(parts[i].equals("dev")) iface=parts[i+1];
            if(parts[i].equals("lladdr")) mac=parts[i+1];
        }
        if(!Objects.equals(iface,wifi.links.getInterfaceName())||state.equals("FAILED")||state.equals("INCOMPLETE")) return;
        String ip=wifi.normalize(parts[0]);
        if(ip==null||!evidence.allowDiscoveredHost(ip)) return;
        metadata(ip,wifi,evidence,"IPv6 neighbor");
        evidence.add(ip,"IPv6 neighbor","neighborState",state);
        if(mac.matches("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}")&&!mac.equals("00:00:00:00:00:00"))
            evidence.add(ip,"IPv6 neighbor","neighborMac",mac.toUpperCase(Locale.ROOT));
        evidence.add(ip,"IPv6 neighbor","reachabilityNote","Cached neighbor observation; current reachability unverified");
    }
    private static void metadata(String ip,WifiIpv6Scope wifi,DeviceEvidence evidence,String source) {
        evidence.add(ip,source,"address",ip);
        evidence.add(ip,source,"networkInterface",wifi.links.getInterfaceName());
        try {evidence.add(ip,source,"addressType",IpAddresses.kind(IpAddresses.literal(ip)));}catch(Exception ignored) { }
    }
}
