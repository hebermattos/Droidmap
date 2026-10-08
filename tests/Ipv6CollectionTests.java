package com.netmap.android;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.*;

/** Regression checks for addresses shared by discovery, identification and Nmap. */
public final class Ipv6CollectionTests {
    private static int assertions;
    private static void check(boolean ok,String message) {
        assertions++;if(!ok) throw new AssertionError(message);
    }
    private static String xml(String ip) {
        return "<?xml version=\"1.0\"?><!DOCTYPE nmaprun><nmaprun><host><address addr=\""+ip+"\" addrtype=\"ipv6\"/><ports><port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/><service name=\"https\" product=\"Example\" version=\"1.2\"/><script id=\"safe-test\" output=\"Observed result\"/></port></ports></host></nmaprun>";
    }
    public static void main(String[] args)throws Exception {
        String expanded=IpAddresses.canonical("fd00::10");
        check(IpAddresses.sameAddress("fd00::10",expanded),"Compare literal IPv6 bytes");
        check(!IpAddresses.sameAddress("fd00::10","fd00::11"),"Do not merge different peers");
        check(IpAddresses.canonical("fe80::10%wlan0").endsWith("%wlan0"),"Preserve interface scope");
        check(IpAddresses.authority("fe80::10%wlan0",631).equals("[fe80::10]:631"),"Bracket IPv6 without leaking zone into HTTP/IPP");
        check(IpAddresses.authority("192.168.1.10",80).equals("192.168.1.10:80"),"Preserve IPv4 Host format");
        check(IpAddresses.inPrefix(InetAddress.getByName("2001:db8:10::1"),64,InetAddress.getByName("2001:db8:10::99")),"Accept local global-unicast prefix");
        check(!IpAddresses.inPrefix(InetAddress.getByName("2001:db8:10::1"),64,InetAddress.getByName("2001:db8:11::99")),"Reject a different Wi-Fi prefix");
        check(IpAddresses.inPrefix(InetAddress.getByName("fd00::1"),63,InetAddress.getByName("fd00:0:0:1::1")),"Support non-byte-aligned prefixes");
        check(!IpAddresses.inPrefix(InetAddress.getByName("fd00::1"),63,InetAddress.getByName("fd00:0:0:2::1")),"Check partial prefix byte");
        check(ScanPlan.parseHosts("2001:db8::1").size()==1,"Allow global syntax for subsequent Wi-Fi validation");
        try {IpAddresses.literal("example.com");throw new AssertionError("Hostname accepted");}catch(IllegalArgumentException|UnknownHostException expected){assertions++;}

        DeviceEvidence evidence=new DeviceEvidence(List.of("fd00::10"),host->host.startsWith("fd00:"));
        check(evidence.allowDiscoveredHost("fd00::20"),"Permit scoped IPv6 discovery");
        check(!evidence.allowDiscoveredHost("2001:db8::20"),"Enforce discovery network policy");
        check(!evidence.allowDiscoveredHost("192.168.1.20"),"Do not expand the IPv4 target list");
        evidence.add("fd00::10","mDNS","serviceName","Media service");
        NmapXmlParser.parse(xml("fd00::10"),evidence);
        check(evidence.snapshot().size()==1,"Compressed Nmap output shares existing device key");
        check(DeviceEvidence.first(evidence.observations(expanded),"openPort").equals("443/tcp"),"Retain Nmap open port");
        check(DeviceEvidence.first(evidence.observations(expanded),"banner").equals("Example 1.2"),"Retain service version");
        NmapXmlParser.parse(xml("fd00::99"),evidence);
        check(evidence.observations("fd00::99").isEmpty(),"Ignore XML for an unrequested host");
        String scoped=IpAddresses.canonical("fe80::10%wlan0");
        DeviceEvidence local=new DeviceEvidence(List.of(scoped));
        NmapXmlParser.parse(xml("fe80::10"),local);
        NmapXmlParser.parseVulnerabilities(xml("fe80::10"),local,List.of(443));
        check(DeviceEvidence.first(local.observations(scoped),"openPort").equals("443/tcp"),"Map zone-free Nmap output to scoped host");
        check(local.observations(scoped).stream().anyMatch(o->o.source.equals("Nmap vulnerabilities")),"Retain scoped vulnerability evidence");
        check(local.resolveHost("fe80::10%other")==null,"Reject an explicit wrong interface");
        DeviceEvidence ambiguous=new DeviceEvidence(List.of("fe80::10%wlan0","fe80::10%other"));
        NmapXmlParser.parse(xml("fe80::10"),ambiguous);
        check(ambiguous.snapshot().isEmpty(),"Do not guess between interfaces");
        try {NmapXmlParser.parse("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><nmaprun/>",local);throw new AssertionError("Entities accepted");}catch(Exception expected){assertions++;}
        DeviceEvidence bounded=new DeviceEvidence(List.of("fd00::1"),host->true);
        for(int i=0;i<256;i++)check(bounded.allowDiscoveredHost("fd00::"+Integer.toHexString(4096+i)),"Discovered address within bound");
        check(!bounded.allowDiscoveredHost("fd00::ffff"),"Limit additional discoveries to 256");
        check(bounded.isDiscoveryLimited(),"Expose discovery budget exhaustion");
        check(bounded.allowDiscoveredHost("fd00::1"),"Existing target still usable at discovery limit");

        ScanPlan plan=new ScanPlan("fd00::1","80",100);
        DeviceEvidence peers=new DeviceEvidence(plan.hosts,host->host.startsWith("fd00:"));
        peers.allowDiscoveredHost("fd00::2");peers.add("fd00::2","mDNS","serviceName","Printer");
        peers.advertise("fd00::2","mDNS","_http._tcp.",12345);
        AtomicInteger connects=new AtomicInteger(),lookups=new AtomicInteger();
        DeviceIdentifier identifier=new DeviceIdentifier(plan,peers,(host,port,timeout)->{connects.incrementAndGet();return TcpScanner.State.CLOSED;},()->{});
        identifier.setHostnameLookup(new DeviceIdentifier.HostnameLookup(){
            public void lookup(String host,long deadline,java.util.function.BooleanSupplier stopped){if(IpAddresses.sameAddress(host,"fd00::2"))lookups.incrementAndGet();}
            public void cancel(){}
        });
        identifier.identify(Collections.emptyList());
        check(connects.get()==1,"Verify the advertised port of a newly discovered IPv6");
        check(lookups.get()==1,"Include discovered IPv6 in PTR identification");
        check(identifier.endpointChecks().size()==1,"Retain discovered-host endpoint checks for exports");

        List<List<String>> commands=new ArrayList<>();
        NmapRunner runner=new NmapRunner(TestNmapTemplates.load(),command->{commands.add(new ArrayList<>(command));return new FinishedProcess(xml("fe80::10"));});
        runner.scan("nmap","data","fe80::10%wlan0",List.of(443),200);
        runner.vulnerabilityScan("nmap","data","fe80::10%wlan0",List.of(443),200);
        for(List<String> command:commands) {
            check(command.contains("-6")&&command.contains("-n"),"Use IPv6 and disable unbound Nmap DNS");
            check(command.contains("-e")&&command.contains("wlan0"),"Select Wi-Fi scope for Nmap");
            check(command.get(command.size()-1).equals("fe80::10"),"Separate interface zone from literal target");
        }
        AtomicBoolean cancelled=new AtomicBoolean();AtomicReference<FinishedProcess> launched=new AtomicReference<>();
        NmapRunner cancellable=new NmapRunner(TestNmapTemplates.load(),command->{FinishedProcess process=new FinishedProcess(xml("fd00::1"));launched.set(process);cancelled.set(true);return process;},cancelled::get);
        try {cancellable.scan("nmap","data","fd00::1",List.of(80),100);throw new AssertionError("Cancellation ignored");}catch(IOException expected){assertions++;}
        check(launched.get().destroyed,"Cancellation destroys the Nmap process");
        System.out.println("PASS: "+assertions+" IPv6 collection assertions");
    }
    private static final class FinishedProcess extends Process {
        private final InputStream input;boolean destroyed;
        FinishedProcess(String xml){input=new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));}
        public InputStream getInputStream(){return input;}
        public InputStream getErrorStream(){return new ByteArrayInputStream(new byte[0]);}
        public OutputStream getOutputStream(){return new ByteArrayOutputStream();}
        public int waitFor(){return 0;}
        public boolean waitFor(long timeout,TimeUnit unit){return true;}
        public int exitValue(){return 0;}
        public void destroy(){destroyed=true;}
        public Process destroyForcibly(){destroyed=true;return this;}
    }
}
