package com.netmap.android;

import java.util.*;

public final class NmapTargetTests {
    private static int assertions;
    private static void check(boolean ok,String message) {assertions++;if(!ok)throw new AssertionError(message);}
    public static void main(String[] args) {
        for(ScanPlan.Mode mode:ScanPlan.Mode.values()) {
            ScanPlan plan=new ScanPlan("192.168.0.0/24","80",200,mode);
            DeviceEvidence evidence=new DeviceEvidence(plan.hosts,host->host.startsWith("fd00:"));
            for(int i=1;i<=16;i++) {
                String ipv6="fd00::"+Integer.toHexString(i);
                check(evidence.allowDiscoveredHost(ipv6),"Admit IPv6");
                evidence.add(ipv6,"mDNS","serviceName","Test peer");
            }
            evidence.add("192.168.0.10","Nmap","scanStatus","Failed");
            List<String> targets=NmapTargets.collect(plan,evidence);
            check(targets.size()==270,"Both modes include all 254 planned IPs plus 16 IPv6 addresses");
            check(targets.contains("192.168.0.254"),"Last silent IPv4 target retained");
            check(targets.contains(IpAddresses.canonical("fd00::10")),"IPv6 beyond old four/eight budgets retained");
            check(new HashSet<>(targets).size()==targets.size(),"Planned/discovered target deduplication");
            check(targets.subList(0,254).equals(plan.hosts),"Planned order retained");
            check(!targets.contains("8.8.8.8"),"No off-scope target invented");
        }
        ScanPlan plan=new ScanPlan("fd00::1","80",200);
        DeviceEvidence evidence=new DeviceEvidence(plan.hosts);
        evidence.add("fd00::1","IPv6 local","addressOrigin","This phone");
        check(NmapTargets.collect(plan,evidence).equals(List.of(IpAddresses.canonical("fd00::1"))),"Explicitly selected phone IPv6 included once");
        System.out.println("PASS: "+assertions+" Nmap all-target assertions");
    }
}
