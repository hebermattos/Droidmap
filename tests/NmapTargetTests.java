package com.netmap.android;

import java.util.*;

public final class NmapTargetTests {
    private static int assertions;
    private static void check(boolean ok,String message) {assertions++;if(!ok)throw new AssertionError(message);}
    public static void main(String[] args) {
        for(ScanPlan.Mode mode:ScanPlan.Mode.values()) {
            ScanPlan plan=new ScanPlan("192.168.0.0/24","80,443",200,mode);
            DeviceEvidence evidence=new DeviceEvidence(plan.hosts,host->host.startsWith("fd00:"));
            List<TcpScanner.Result> checks=new ArrayList<>();
            for(int i=1;i<=16;i++) {
                String ipv4="192.168.0."+i, ipv6="fd00::"+Integer.toHexString(i);
                check(evidence.allowDiscoveredHost(ipv6),"Admit IPv6");
                evidence.add(ipv6,"mDNS","serviceName","Test peer");
                checks.add(new TcpScanner.Result(ipv4,80,TcpScanner.State.OPEN));
                checks.add(new TcpScanner.Result(ipv4,443,TcpScanner.State.CLOSED));
                checks.add(new TcpScanner.Result(ipv6,8081,TcpScanner.State.OPEN));
            }
            checks.add(new TcpScanner.Result("192.168.0.254",80,TcpScanner.State.NO_RESPONSE));
            checks.add(new TcpScanner.Result("192.168.0.253",80,TcpScanner.State.ERROR));
            checks.add(new TcpScanner.Result("192.168.0.252",80,TcpScanner.State.CLOSED));
            checks.add(new TcpScanner.Result("8.8.8.8",80,TcpScanner.State.OPEN));
            checks.add(new TcpScanner.Result("192.168.0.1",80,TcpScanner.State.OPEN));
            Map<String,LinkedHashSet<Integer>> targets=NmapTargets.collect(checks,evidence);
            check(targets.size()==32,"No four/eight host cap for found IPv4 and IPv6 devices");
            check(!targets.containsKey("192.168.0.254")&&!targets.containsKey("192.168.0.253")&&!targets.containsKey("192.168.0.252"),"Exclude silent/error/closed-only devices");
            check(targets.get("192.168.0.1").equals(new LinkedHashSet<>(List.of(80))),"Only actual open ports, deduplicated");
            check(targets.get(IpAddresses.canonical("fd00::10")).equals(new LinkedHashSet<>(List.of(8081))),"IPv6 verified advertised endpoint beyond old budget retained");
            check(!targets.containsKey("8.8.8.8"),"Reject out-of-scope result");
            evidence.allowDiscoveredHost("fd00::99");
            evidence.add("fd00::99","mDNS","serviceName","Unverified peer");
            check(!NmapTargets.collect(checks,evidence).containsKey(IpAddresses.canonical("fd00::99")),"Discovery without an open TCP check is not scanned");
        }
        DeviceEvidence evidence=new DeviceEvidence(List.of("192.168.0.1"));
        check(NmapTargets.collect(Collections.emptyList(),evidence).isEmpty(),"No open ports means no Nmap targets");
        check(NmapTargets.collect(List.of(new TcpScanner.Result("192.168.0.1",0,TcpScanner.State.OPEN)),evidence).isEmpty(),"Reject invalid port");
        System.out.println("PASS: "+assertions+" Nmap open-target assertions");
    }
}
