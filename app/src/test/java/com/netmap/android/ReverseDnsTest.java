package com.netmap.android;

import org.junit.Test;
import static org.junit.Assert.*;
import org.xbill.DNS.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ReverseDnsTest {
    private Message reply(Message query) throws Exception {
        Message response=new Message(query.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        response.addRecord(query.getQuestion(),Section.QUESTION);
        response.addRecord(new PTRRecord(query.getQuestion().getName(),DClass.IN,60,Name.fromString("printer.lan.")),Section.ANSWER);
        return response;
    }
    @Test public void resolvesNewIpv6AndStripsInterfaceFromPtrQuestion() throws Exception {
        ScanPlan plan=new ScanPlan("fd00::1","80",200);
        DeviceEvidence evidence=new DeviceEvidence(plan.hosts,host->host.startsWith("fd00:"));
        assertTrue(evidence.allowDiscoveredHost("fd00::42"));
        AtomicInteger calls=new AtomicInteger();
        ReverseDns dns=new ReverseDns(Collections.singletonList(InetAddress.getByName("192.168.1.1")),plan,evidence,socket->{},UUID.randomUUID().toString(),(query,server,tcp,deadline,stopped)->{
            calls.incrementAndGet();assertTrue(query.getQuestion().getName().toString().endsWith("ip6.arpa."));
            try{return reply(query).toWire();}catch(Exception e){throw new java.io.IOException(e);}
        });
        dns.lookup("fd00::42",Long.MAX_VALUE,()->false);
        assertEquals(1,calls.get());
        assertEquals("printer.lan",DeviceEvidence.first(evidence.observations("fd00::42"),"dnsHostname"));
        assertEquals(ReverseMap.fromAddress(InetAddress.getByName("fe80::42")),ReverseDns.query("fe80::42%missingInterface").getQuestion().getName());
    }
    @Test public void extractsMatchingPtr() throws Exception {
        Message query=ReverseDns.query("192.168.1.42");
        assertEquals("42.1.168.192.in-addr.arpa.",query.getQuestion().getName().toString());
        assertEquals(Collections.singletonList("printer.lan"),ReverseDns.names(reply(query).toWire(),query));
    }
    @Test public void rejectsMismatchedIdQuestionAndOwner() throws Exception {
        Message query=ReverseDns.query("192.168.1.42"),response=reply(query);
        response.getHeader().setID((query.getHeader().getID()+1)&65535);
        assertTrue(ReverseDns.names(response.toWire(),query).isEmpty());
        response=reply(ReverseDns.query("192.168.1.43")); response.getHeader().setID(query.getHeader().getID());
        assertTrue(ReverseDns.names(response.toWire(),query).isEmpty());
        response=reply(query); response.removeAllRecords(Section.ANSWER);
        response.addRecord(new PTRRecord(Name.fromString("43.1.168.192.in-addr.arpa."),DClass.IN,60,Name.fromString("wrong.lan.")),Section.ANSWER);
        assertTrue(ReverseDns.names(response.toWire(),query).isEmpty());
    }
    @Test public void rejectsTruncatedNegativeAndNonResponses() throws Exception {
        Message query=ReverseDns.query("192.168.1.42"),response=reply(query);
        response.getHeader().setFlag(Flags.TC); assertTrue(ReverseDns.names(response.toWire(),query).isEmpty());
        response=reply(query); response.getHeader().setRcode(Rcode.NXDOMAIN); assertTrue(ReverseDns.names(response.toWire(),query).isEmpty());
        assertTrue(ReverseDns.names(query.toWire(),query).isEmpty());
    }
    @Test(expected=java.io.IOException.class) public void rejectsMalformedPacket() throws Exception {
        ReverseDns.names(new byte[]{1,2,3},ReverseDns.query("192.168.1.42"));
    }
    @Test public void followsAliasesAndUsesTtlCache() throws Exception {
        ScanPlan plan=new ScanPlan("192.168.1.42","80",200,ScanPlan.Mode.FAST);DeviceEvidence evidence=new DeviceEvidence(plan.hosts);
        java.util.concurrent.atomic.AtomicLong cacheTime=new java.util.concurrent.atomic.AtomicLong();
        java.util.concurrent.atomic.AtomicInteger calls=new java.util.concurrent.atomic.AtomicInteger();String scope=java.util.UUID.randomUUID().toString();
        ReverseDns.Transport transport=(query,server,tcp,deadline,stopped)-> {
            calls.incrementAndGet();Message response=new Message(query.getHeader().getID());response.getHeader().setFlag(Flags.QR);response.addRecord(query.getQuestion(),Section.QUESTION);
            try {
                Name alias=Name.fromString("alias.lan.");
                if(query.getQuestion().getName().equals(alias)) response.addRecord(new PTRRecord(alias,DClass.IN,60,Name.fromString("printer.lan.")),Section.ANSWER);
                else response.addRecord(new CNAMERecord(query.getQuestion().getName(),DClass.IN,30,alias),Section.ANSWER);
                return response.toWire();
            } catch(Exception e) {throw new java.io.IOException(e);}
        };
        java.util.List<InetAddress> servers=Collections.singletonList(InetAddress.getByName("192.168.1.1"));
        new ReverseDns(servers,plan,evidence,socket->{},scope,transport,cacheTime::get).lookup("192.168.1.42",Long.MAX_VALUE,()->false);
        assertEquals(2,calls.get());assertEquals("printer.lan",DeviceEvidence.first(evidence.observations("192.168.1.42"),"dnsHostname"));
        new ReverseDns(servers,plan,new DeviceEvidence(plan.hosts),socket->{},scope,transport,cacheTime::get).lookup("192.168.1.42",Long.MAX_VALUE,()->false);assertEquals(2,calls.get());
        cacheTime.set(java.util.concurrent.TimeUnit.SECONDS.toNanos(31));
        new ReverseDns(servers,plan,new DeviceEvidence(plan.hosts),socket->{},scope,transport,cacheTime::get).lookup("192.168.1.42",Long.MAX_VALUE,()->false);assertEquals(4,calls.get());
        new ReverseDns(servers,plan,new DeviceEvidence(plan.hosts),socket->{},scope+"other-network",transport).lookup("192.168.1.42",Long.MAX_VALUE,()->false);assertEquals(6,calls.get());
    }
    @Test public void tcpFallbackAndZeroTtlAreBounded() throws Exception {
        ScanPlan plan=new ScanPlan("192.168.1.42","80",200,ScanPlan.Mode.FAST);DeviceEvidence evidence=new DeviceEvidence(plan.hosts);
        java.util.concurrent.atomic.AtomicInteger udp=new java.util.concurrent.atomic.AtomicInteger(),tcpCalls=new java.util.concurrent.atomic.AtomicInteger();
        ReverseDns.Transport transport=(query,server,tcp,deadline,stopped)-> {
            Message response=new Message(query.getHeader().getID());response.getHeader().setFlag(Flags.QR);response.addRecord(query.getQuestion(),Section.QUESTION);
            if(!tcp) {udp.incrementAndGet();response.getHeader().setFlag(Flags.TC);} else {tcpCalls.incrementAndGet();try{response.addRecord(new PTRRecord(query.getQuestion().getName(),DClass.IN,0,Name.fromString("zero.lan.")),Section.ANSWER);}catch(Exception e){throw new java.io.IOException(e);}}
            return response.toWire();
        };
        ReverseDns dns=new ReverseDns(Collections.singletonList(InetAddress.getByName("192.168.1.1")),plan,evidence,socket->{},java.util.UUID.randomUUID().toString(),transport);
        dns.lookup("192.168.1.42",Long.MAX_VALUE,()->false);dns.lookup("192.168.1.42",Long.MAX_VALUE,()->false);assertEquals(2,udp.get());assertEquals(2,tcpCalls.get());
        dns.lookup("192.168.1.42",System.nanoTime()-1,()->false);assertEquals(2,udp.get());
    }
    @Test public void aliasCyclesDoNotCreateEvidence() throws Exception {
        ScanPlan plan=new ScanPlan("192.168.1.42","80",200,ScanPlan.Mode.FAST);DeviceEvidence evidence=new DeviceEvidence(plan.hosts);java.util.concurrent.atomic.AtomicInteger count=new java.util.concurrent.atomic.AtomicInteger();
        ReverseDns dns=new ReverseDns(Collections.singletonList(InetAddress.getByName("192.168.1.1")),plan,evidence,socket->{},java.util.UUID.randomUUID().toString(),(query,server,tcp,deadline,stopped)-> {
            count.incrementAndGet();Message response=new Message(query.getHeader().getID());response.getHeader().setFlag(Flags.QR);response.addRecord(query.getQuestion(),Section.QUESTION);response.addRecord(new CNAMERecord(query.getQuestion().getName(),DClass.IN,60,query.getQuestion().getName()),Section.ANSWER);return response.toWire();
        });dns.lookup("192.168.1.42",Long.MAX_VALUE,()->false);assertEquals(1,count.get());assertTrue(evidence.snapshot().isEmpty());
    }
    @Test public void cancellationClosesActiveSocket() throws Exception {
        ScanPlan plan=new ScanPlan("192.168.1.42","80",200,ScanPlan.Mode.FAST);
        java.util.concurrent.CountDownLatch entered=new java.util.concurrent.CountDownLatch(1),release=new java.util.concurrent.CountDownLatch(1);
        DatagramSocket[] active={null};
        ReverseDns dns=new ReverseDns(Collections.singletonList(InetAddress.getByName("192.168.1.1")),plan,new DeviceEvidence(plan.hosts),socket->{
            active[0]=socket; entered.countDown();
            try { release.await(); } catch(InterruptedException e) { Thread.currentThread().interrupt(); }
            throw new java.io.IOException("Test transport ended");
        });
        Thread worker=new Thread(()->dns.lookup("192.168.1.42",Long.MAX_VALUE,()->false)); worker.start();
        try { assertTrue(entered.await(2,java.util.concurrent.TimeUnit.SECONDS)); dns.cancel(); assertTrue(active[0].isClosed()); }
        finally { release.countDown(); worker.join(2000); }
        assertFalse(worker.isAlive());
    }
    @Test public void capsNamesAndIgnoresNonPtrRecords() throws Exception {
        Message query=ReverseDns.query("192.168.1.42"),response=reply(query);
        for(int i=0;i<8;i++) response.addRecord(new PTRRecord(query.getQuestion().getName(),DClass.IN,60,Name.fromString("device"+i+".lan.")),Section.ANSWER);
        assertEquals(4,ReverseDns.names(response.toWire(),query).size());
        response.removeAllRecords(Section.ANSWER);
        response.addRecord(new CNAMERecord(query.getQuestion().getName(),DClass.IN,60,Name.fromString("alias.lan.")),Section.ANSWER);
        assertTrue(ReverseDns.names(response.toWire(),query).isEmpty());
    }
    @Test public void restrictsResolversAndTargetsAndCancellation() throws Exception {
        assertTrue(ReverseDns.privateIpv4(InetAddress.getByName("10.0.0.1")));
        assertTrue(ReverseDns.privateIpv4(InetAddress.getByName("172.31.1.1")));
        assertFalse(ReverseDns.privateIpv4(InetAddress.getByName("172.32.1.1")));
        assertFalse(ReverseDns.privateIpv4(InetAddress.getByName("8.8.8.8")));
        assertFalse(ReverseDns.privateIpv4(InetAddress.getByName("::1")));
        ScanPlan plan=new ScanPlan("192.168.1.42","80",200,ScanPlan.Mode.FAST);
        DeviceEvidence evidence=new DeviceEvidence(plan.hosts); int[] calls={0};
        ReverseDns dns=new ReverseDns(Collections.singletonList(InetAddress.getByName("192.168.1.1")),plan,evidence,socket->{calls[0]++;});
        dns.lookup("192.168.1.43",Long.MAX_VALUE,()->false);
        dns.lookup("192.168.1.42",System.nanoTime()-1,()->false);
        dns.lookup("192.168.1.42",Long.MAX_VALUE,()->true);
        dns.cancel(); dns.lookup("192.168.1.42",Long.MAX_VALUE,()->false);
        assertEquals(0,calls[0]); assertTrue(evidence.snapshot().isEmpty());
        ReverseDns publicDns=new ReverseDns(Collections.singletonList(InetAddress.getByName("8.8.8.8")),plan,evidence,socket->{calls[0]++;});
        publicDns.lookup("192.168.1.42",Long.MAX_VALUE,()->false); assertEquals(0,calls[0]);
    }
}
