package com.netmap.android;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.*;

public class ImprovementsTest {
    private void attribute(DataOutputStream out,String name,String value) throws Exception {
        byte[] n=name.getBytes(StandardCharsets.UTF_8),v=value.getBytes(StandardCharsets.UTF_8);
        out.writeByte(0x42);out.writeShort(n.length);out.write(n);out.writeShort(v.length);out.write(v);
    }
    private byte[] printerReply() throws Exception {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
        out.writeShort(0x0101);out.writeShort(0);out.writeInt(Ipp.REQUEST_ID);out.writeByte(4);
        attribute(out,"printer-name","Office printer");attribute(out,"printer-make-and-model","Brother HL-L2350DW");out.writeByte(3);return bytes.toByteArray();
    }
    @Test public void ippReadOnlyRequestAndBoundedReply() throws Exception {
        byte[] request=Ipp.request("ipp://192.168.1.1:631/ipp/print");
        DataInputStream in=new DataInputStream(new ByteArrayInputStream(request));assertEquals(0x0101,in.readUnsignedShort());assertEquals(0x000b,in.readUnsignedShort());assertEquals(Ipp.REQUEST_ID,in.readInt());
        assertEquals("Brother HL-L2350DW",Ipp.parse(printerReply()).get("modelName"));
        byte[] bad=printerReply();bad[7]++;assertTrue(Ipp.parse(bad).isEmpty());
        bad=printerReply();bad[2]=4;assertTrue(Ipp.parse(bad).isEmpty());
        byte[] reply=printerReply();for(int i=0;i<reply.length;i++) assertTrue(Ipp.parse(Arrays.copyOf(reply,i)).isEmpty());
        assertNull(Ipp.resource("../job"));assertNull(Ipp.resource("/ipp\r\nHost: evil"));assertNull(Ipp.resource("http://external/printer"));
        assertEquals("/ipp/print",Ipp.resource("ipp/print"));
        assertTrue(DeviceIdentifier.isIppEndpoint(631,""));assertTrue(DeviceIdentifier.isIppEndpoint(1234,"_ipp._tcp."));
        assertFalse(DeviceIdentifier.isIppEndpoint(631,"_ipps._tcp."));assertFalse(DeviceIdentifier.isIppEndpoint(9100,"_printer._tcp."));
    }
    @Test public void httpBinaryAndChunkedFraming() throws Exception {
        byte[] body=printerReply();ByteArrayOutputStream raw=new ByteArrayOutputStream();
        raw.write(("HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: "+body.length+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));raw.write(body);
        assertArrayEquals(body,HttpReply.body(raw.toByteArray(),"application/ipp"));
        assertTrue(HttpReply.body(Arrays.copyOf(raw.toByteArray(),raw.size()-1),"application/ipp").length==0);
        raw.reset();raw.write(("HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nTransfer-Encoding: chunked\r\n\r\n"+Integer.toHexString(body.length)+"\r\n").getBytes(StandardCharsets.US_ASCII));raw.write(body);raw.write("\r\n0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(body,HttpReply.body(raw.toByteArray(),"application/ipp"));assertEquals(0,HttpReply.body(raw.toByteArray(),"text/html").length);
    }
    @Test public void profilesExplainAndWithholdConflicts() {
        DeviceEvidence evidence=new DeviceEvidence(Collections.singleton("192.168.1.1"));
        evidence.add("192.168.1.1","mDNS TXT","modelHint","Brother HL-L2350DW");evidence.add("192.168.1.1","mDNS","serviceType","_ipp._tcp.");
        DeviceProfile profile=new DeviceProfile(evidence.observations("192.168.1.1"));assertEquals("Brother",profile.manufacturer);assertTrue(profile.type.toLowerCase(Locale.ROOT).contains("printer"));assertFalse(profile.reasons.isEmpty());
        evidence.add("192.168.1.1","IPP","modelName","Brother HL-L2350DW");assertEquals("Corroborated, unverified",new DeviceProfile(evidence.observations("192.168.1.1")).confidence);
        evidence.add("192.168.1.1","UPnP","manufacturer","Samsung");evidence.add("192.168.1.1","IPP","manufacturer","Brother");profile=new DeviceProfile(evidence.observations("192.168.1.1"));assertEquals("",profile.manufacturer);assertNotEquals("Corroborated, unverified",profile.confidence);
        evidence=new DeviceEvidence(Collections.singleton("192.168.1.1"));evidence.add("192.168.1.1","DNS PTR","dnsHostname","Samsung-TV.lan");assertEquals("",new DeviceProfile(evidence.observations("192.168.1.1")).manufacturer);
    }
    @Test public void adaptivePolicyLimitsAndCompleteInventory() throws Exception {
        AdaptivePolicy policy=new AdaptivePolicy(500);for(int i=0;i<32;i++) policy.observe(TcpScanner.State.NO_RESPONSE,500);assertEquals(32,policy.concurrency());assertEquals(500,policy.timeout());
        for(int i=0;i<64;i++) policy.observe(TcpScanner.State.OPEN,10);assertEquals(32,policy.concurrency());
        policy.observe(TcpScanner.State.OPEN,10000);assertEquals(3000,policy.timeout());
        AtomicInteger active=new AtomicInteger(),maximum=new AtomicInteger(),count=new AtomicInteger();
        TcpScanner scanner=new TcpScanner((host,port,timeout)-> {int n=active.incrementAndGet();maximum.accumulateAndGet(n,Math::max);try{Thread.sleep(2);}catch(InterruptedException e){Thread.currentThread().interrupt();}finally{active.decrementAndGet();}count.incrementAndGet();return host.endsWith("1")?TcpScanner.State.OPEN:TcpScanner.State.NO_RESPONSE;});
        ScanPlan plan=new ScanPlan("192.168.1.0/27","80,81,82",100,ScanPlan.Mode.FAST,true);List<TcpScanner.Result> results=scanner.scan(plan,(r,c,t)->{});
        assertEquals(plan.hosts.size()*plan.ports.size(),results.size());assertEquals(results.size(),count.get());assertTrue(maximum.get()<=32);
        Set<String> pairs=new HashSet<>();for(TcpScanner.Result result:results) {assertTrue(result.timeoutMs>=100);pairs.add(result.host+":"+result.port);}assertEquals(results.size(),pairs.size());
    }
    private JSONObject report(String target,String ip,int port,boolean cancelled) throws Exception {
        JSONObject r=new JSONObject();r.put("target",target);r.put("finishedAtEpochMs",123456);r.put("cancelled",cancelled);
        JSONArray checks=new JSONArray();checks.put(new JSONObject().put("ip",ip).put("port",port).put("state","OPEN"));r.put("checks",checks);r.put("devices",new JSONArray());return r;
    }
    @Test public void historyComparisonPersistenceAndCancellation() throws Exception {
        File directory=java.nio.file.Files.createTempDirectory("netmap-history-").toFile();File file=new File(directory,"history.json");ScanHistory history=new ScanHistory(file);
        ScanPlan plan=new ScanPlan("192.168.1.0/24","80,81",100);
        assertTrue(history.save(report("192.168.1.0/24","192.168.1.1",80,false),plan).startsWith("First"));
        String delta=history.save(report("192.168.1.0/24","192.168.1.1",81,false),plan);assertTrue(delta.contains("newly observed open ports: [81]"));assertTrue(delta.contains("no longer observed open: [80]"));
        delta=history.save(report("192.168.1.0/24","192.168.1.2",80,false),plan);assertTrue(delta.contains("New responder: 192.168.1.2"));assertTrue(delta.contains("Not observed this scan: 192.168.1.1"));
        int before=history.load().length();history.save(report("192.168.1.0/24","192.168.1.3",80,true),plan);assertEquals(before,history.load().length());
        ScanPlan other=new ScanPlan("192.168.1.0/24","80",100);assertTrue(history.save(report("192.168.1.0/24","192.168.1.2",80,false),other).startsWith("First"));
        for(int i=0;i<30;i++) history.save(report("192.168.1.0/24","192.168.1.2",80,false),plan);assertEquals(20,new ScanHistory(file).load().length());
        assertTrue(ScanHistory.describe(history.load().getJSONObject(0)).contains("192.168.1.2"));
        java.nio.file.Files.write(file.toPath(),"broken".getBytes(StandardCharsets.UTF_8));try{history.load();fail("Corrupt history must be reported");}catch(JSONException expected){}
        java.nio.file.Files.delete(file.toPath());java.nio.file.Files.delete(directory.toPath());
    }
}
