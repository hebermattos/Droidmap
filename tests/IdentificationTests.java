package com.netmap.android;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public final class IdentificationTests {
    private static int assertions;
    private static void check(boolean condition,String reason) { assertions++; if(!condition) throw new AssertionError(reason); }
    public static void main(String[] args) throws Exception {
        DeviceEvidence evidence=new DeviceEvidence(List.of("192.168.0.10"));
        evidence.add("192.168.0.11","mDNS","serviceName","Outside target");
        check(evidence.snapshot().isEmpty(),"Ignore out-of-scope evidence");
        evidence.add("192.168.0.10","mDNS","serviceName","Living room TV\n");
        evidence.add("192.168.0.10","mDNS","serviceName","Living room TV\n");
        check(evidence.snapshot().get("192.168.0.10").size()==1,"Deduplicate and clean observations");
        check(DeviceEvidence.first(evidence.snapshot().get("192.168.0.10"),"serviceName").equals("Living room TV"),"Reported name retained");
        check(DeviceEvidence.probableType(evidence.snapshot().get("192.168.0.10")).equals("Unknown"),"Name alone does not imply a model or type");
        evidence.add("192.168.0.10","mDNS","serviceType","_googlecast._tcp.");
        check(DeviceEvidence.probableType(evidence.snapshot().get("192.168.0.10")).equals("Google Cast receiver"),"Infer service capability");
        Map<String,List<DeviceEvidence.Observation>> snapshot=evidence.snapshot(); snapshot.clear();
        check(evidence.snapshot().size()==1,"Independent snapshots");
        for(int i=0;i<100;i++) evidence.add("192.168.0.10","test","item",String.valueOf(i));
        check(evidence.snapshot().get("192.168.0.10").size()==48,"Evidence count bounded");
        check(DeviceEvidence.clean("a".repeat(1000)).length()==300,"Evidence size bounded");
        Map<String,String> h=DeviceEvidence.headers("HTTP/1.1 200 OK\r\nSERVER: RouterOS\r\nLocation: http://192.168.0.10/device.xml\r\n\r\nServer: forged-body");
        check(h.get("server").equals("RouterOS") && !h.containsKey("forged-body"),"Headers separate from body");
        check(DeviceEvidence.title("<HTML><TITLE>Home &amp; Office</TITLE></HTML>").equals("Home & Office"),"HTML title case and entities");
        Map<String,String> fields=DeviceEvidence.upnpFields("<root><device><friendlyName>Office &amp; TV</friendlyName><manufacturer>Example</manufacturer><modelName>Model 7</modelName><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType></device></root>");
        check(fields.get("friendlyName").equals("Office & TV") && fields.get("modelName").equals("Model 7"),"UPnP metadata");
        check(DeviceEvidence.upnpFields("<!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><friendlyName>&x;</friendlyName>").isEmpty(),"Reject entity-bearing XML");
        check(DeviceEvidence.upnpFields("x".repeat(65537)).isEmpty(),"Reject oversized XML");
        check(DeviceIdentifier.allowedLocation("http://192.168.0.10:8000/description.xml?a=1","192.168.0.10"),"Same-sender description accepted");
        for(String bad:List.of("http://192.168.0.11/a","http://example.com/a","http://127.0.0.1/a","file:///etc/passwd","http://user@192.168.0.10/a","http://192.168.0.10:0/a","http://192.168.0.10:65536/a","http://192.168.0.10/a#b","http://192.168.0.10/\r\nInjected: yes","https://192.168.0.10/a")) check(!DeviceIdentifier.allowedLocation(bad,"192.168.0.10"),"Reject untrusted description location: "+bad);
        byte[] query=NetBios.query(0x1234); check(query.length==50 && query[13]=='C' && query[14]=='K' && query[47]==0x21,"Wildcard node-status query");
        ByteArrayOutputStream bytes=new ByteArrayOutputStream(); DataOutputStream data=new DataOutputStream(bytes);
        data.writeShort(0x1234); data.writeShort(0x8400); data.writeShort(0); data.writeShort(1); data.writeInt(0);
        data.writeByte(0); data.writeShort(0x21); data.writeShort(1); data.writeInt(0); data.writeShort(25);
        data.writeByte(1); data.write("OFFICE-PC      ".getBytes(StandardCharsets.US_ASCII)); data.writeByte(0); data.writeShort(0x0400); data.write(new byte[]{2,3,4,5,6,7});
        byte[] response=bytes.toByteArray(); Map<String,String> netbios=NetBios.parse(response,0x1234);
        check(netbios.get("netbiosName").equals("OFFICE-PC"),"NetBIOS name parsed");
        check(netbios.get("reportedMac").equals("02:03:04:05:06:07"),"NetBIOS self-reported MAC");
        check(NetBios.parse(response,0x5678).isEmpty(),"Ignore mismatched transaction");
        for(int size=0;size<response.length-6;size++) check(NetBios.parse(Arrays.copyOf(response,size),0x1234).isEmpty(),"Truncated packets rejected");
        byte[] invalid=response.clone(); invalid[23]=(byte)255; check(NetBios.parse(invalid,0x1234).isEmpty(),"Invalid name count rejected");
        // Exercise the production socket reader against a real local server.
        DeviceIdentifier reader=new DeviceIdentifier(new ScanPlan("192.168.0.10","80",100),new DeviceEvidence(List.of("192.168.0.10")));
        ExecutorService executor=Executors.newSingleThreadExecutor();
        try(ServerSocket server=new ServerSocket(0,1,InetAddress.getLoopbackAddress())) {
            Future<?> served=executor.submit(() -> {
                try(Socket client=server.accept()) { client.getOutputStream().write("HTTP/1.0 200 OK\r\nServer: Test\r\n\r\n<title>Test device</title>".getBytes(StandardCharsets.US_ASCII)); }
                catch(IOException e) { throw new RuntimeException(e); }
            });
            String actual=reader.read("127.0.0.1",server.getLocalPort(),null,4096);
            check(actual.startsWith("HTTP/1.0"),"Real bounded banner read"); served.get(2,TimeUnit.SECONDS);
        } finally { executor.shutdownNow(); reader.cancel(); }
        DeviceIdentifier boundedReader=new DeviceIdentifier(new ScanPlan("192.168.0.10","80",100),new DeviceEvidence(List.of("192.168.0.10")));
        ExecutorService capServer=Executors.newSingleThreadExecutor();
        try(ServerSocket server=new ServerSocket(0,1,InetAddress.getLoopbackAddress())) {
            Future<?> served=capServer.submit(() -> {
                try(Socket client=server.accept()) { client.getOutputStream().write(new byte[4096]); } catch(IOException e) { throw new RuntimeException(e); }
            });
            check(boundedReader.read("127.0.0.1",server.getLocalPort(),"GET / HTTP/1.0\r\n\r\n",32).length()==32,"Network read byte cap enforced");
            served.get(2,TimeUnit.SECONDS);
        } finally { capServer.shutdownNow(); boundedReader.cancel(); }
        DeviceIdentifier cancellable=new DeviceIdentifier(new ScanPlan("192.168.0.10","80",100),new DeviceEvidence(List.of("192.168.0.10")));
        ExecutorService cancelWorkers=Executors.newFixedThreadPool(2); CountDownLatch connected=new CountDownLatch(1);
        try(ServerSocket server=new ServerSocket(0,1,InetAddress.getLoopbackAddress())) {
            Future<?> served=cancelWorkers.submit(() -> {
                try(Socket client=server.accept()) { connected.countDown(); while(client.getInputStream().read()!=-1) {} } catch(IOException ignored) {}
            });
            Future<String> reading=cancelWorkers.submit(() -> cancellable.read("127.0.0.1",server.getLocalPort(),null,4096));
            check(connected.await(2,TimeUnit.SECONDS),"Identification socket active"); cancellable.cancel();
            check(reading.get(1,TimeUnit.SECONDS).isEmpty(),"Cancellation closes active identification socket"); served.get(2,TimeUnit.SECONDS);
        } finally { cancelWorkers.shutdownNow(); cancellable.cancel(); }
        check(reader.read("127.0.0.1",1,null,4096).isEmpty(),"Cancelled reader starts no connection");
        DeviceEvidence announced=new DeviceEvidence(List.of("192.168.0.10"));
        announced.advertise("192.168.0.11","mDNS","_http._tcp.",12345);
        announced.advertise("192.168.0.10","mDNS","_http._udp.",12345);
        announced.advertise("192.168.0.10","mDNS","_http._tcp.",0);
        announced.advertise("192.168.0.10","mDNS","_http._tcp.",65536);
        check(announced.endpoints().isEmpty(),"Announcements restricted to target TCP endpoints and valid ports");
        announced.advertise("192.168.0.10","mDNS","_http._tcp.",12345);
        announced.advertise("192.168.0.10","mDNS","_http._tcp.",12345);
        check(announced.endpoints().get("192.168.0.10").size()==1,"Deduplicate announced ports");
        check(announced.endpoints().get("192.168.0.10").get(0).port==12345,"Retain a nonstandard advertised port");
        for(int port=20000;port<20100;port++) announced.advertise("192.168.0.10","mDNS","_http._tcp.",port);
        check(announced.endpoints().get("192.168.0.10").size()==16,"Advertised endpoints capped per host");
        Map<String,List<DeviceEvidence.Endpoint>> ep=announced.endpoints(); ep.get("192.168.0.10").clear();
        check(announced.endpoints().get("192.168.0.10").size()==16,"Independent endpoint snapshot");
        DeviceIdentifier scoped=new DeviceIdentifier(new ScanPlan("192.168.0.10","80",100),announced);
        check(scoped.verifyEndpoint("127.0.0.1",80)==null,"Cannot probe an out-of-target announcement");
        check(scoped.verifyEndpoint("192.168.0.10",65536)==null,"Cannot probe an invalid port"); scoped.cancel();
        check(scoped.verifyEndpoint("192.168.0.10",12345)==null,"Cancelled announced endpoint not probed");
        check(DeviceIdentifier.isHttpEndpoint(12345,"_http._tcp."),"HTTP announcement enables fingerprinting on nonstandard ports");
        check(!DeviceIdentifier.isHttpEndpoint(12345,"_https._tcp."),"Do not send plaintext HTTP to an advertised TLS service");
        check(!DeviceIdentifier.isHttpEndpoint(9100,"_printer._tcp."),"Do not send HTTP to a printing service");
        check(!DeviceIdentifier.isHttpEndpoint(12345,""),"Unknown nonstandard port receives no guessed HTTP request");
        // Inject transport routing only, retaining real loopback sockets and production target validation.
        TcpScanner localTransport=new TcpScanner();
        try(ServerSocket server=new ServerSocket(0,1,InetAddress.getLoopbackAddress())) {
            String ip="192.168.0.10";
            DeviceIdentifier actualProbe=new DeviceIdentifier(new ScanPlan(ip,"80",500),new DeviceEvidence(List.of(ip)),
                (host,port,timeout) -> localTransport.probe("127.0.0.1",port,timeout));
            TcpScanner.Result open=actualProbe.verifyEndpoint(ip,server.getLocalPort());
            check(open!=null && open.state==TcpScanner.State.OPEN,"Real advertised port outside selected ports is verified open");
            int closed=server.getLocalPort(); server.close();
            check(actualProbe.verifyEndpoint(ip,closed).state==TcpScanner.State.CLOSED,"Advertised service is not assumed open after it closes"); actualProbe.cancel(); localTransport.cancel();
        }
        java.util.concurrent.atomic.AtomicInteger advertisedAttempts=new java.util.concurrent.atomic.AtomicInteger();
        List<Integer> advertisedTimeouts=new ArrayList<>();
        DeviceIdentifier adaptiveEndpoint=new DeviceIdentifier(new ScanPlan("192.168.0.10","80",500,ScanPlan.Mode.COMPLETE),announced,
            (host,port,timeout)-> { advertisedTimeouts.add(timeout); return advertisedAttempts.incrementAndGet()==1?TcpScanner.State.NO_RESPONSE:TcpScanner.State.OPEN; });
        TcpScanner.Result retriedEndpoint=adaptiveEndpoint.verifyEndpoint("192.168.0.10",12345);
        check(retriedEndpoint.state==TcpScanner.State.OPEN && retriedEndpoint.attempts==2 && advertisedTimeouts.equals(List.of(500,1000)),"Advertised endpoint receives bounded adaptive retries"); adaptiveEndpoint.cancel();
        DeviceIdentifier exhaustedEndpoint=new DeviceIdentifier(new ScanPlan("192.168.0.10","80",2500,ScanPlan.Mode.COMPLETE),announced,(host,port,timeout)->TcpScanner.State.NO_RESPONSE);
        check(exhaustedEndpoint.verifyEndpoint("192.168.0.10",12345).timeoutMs==3000,"Reported endpoint timeout matches final attempted timeout"); exhaustedEndpoint.cancel();
        System.out.println("PASS: "+assertions+" identification assertions (scope, parsers, metadata, URLs, NetBIOS, real sockets)");
    }
}
