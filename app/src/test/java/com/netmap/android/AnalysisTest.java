package com.netmap.android;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import org.json.*;

public class AnalysisTest {
    private static final String IP="192.168.1.1";
    @Test public void txtFieldsDoNotTurnVersionsAndProductsIntoModels() {
        assertEquals("reportedOsVersion",MdnsFields.field("_airplay._tcp.","osvers"));
        assertEquals("reportedProduct",MdnsFields.field("_ipp._tcp.","product"));
        assertEquals("modelHint",MdnsFields.field("_googlecast._tcp.","md"));
        assertEquals("reportedMd",MdnsFields.field("_http._tcp.","md"));
        assertEquals("modelHint",MdnsFields.field("_airplay._tcp.","am"));
        assertEquals("modelHint",MdnsFields.field("_ipp._tcp.","ty"));
        assertEquals("reportedTy",MdnsFields.field("_http._tcp.","ty"));
    }
    @Test public void confidenceRequiresAgreementOnTheSameIdentityField() {
        DeviceEvidence e=new DeviceEvidence(Collections.singleton(IP));
        e.add(IP,"mDNS","friendlyName","Example"); e.add(IP,"UPnP","modelName","Example");
        DeviceProfile p=new DeviceProfile(e.observations(IP));
        assertNotEquals(DeviceConfidence.CORROBORATED,p.confidence);
        e.add(IP,"mDNS TXT","modelHint","Example");
        assertEquals(DeviceConfidence.CORROBORATED,new DeviceProfile(e.observations(IP)).modelConfidence);
        e.add(IP,"IPP","modelName","Different"); p=new DeviceProfile(e.observations(IP));
        assertEquals(DeviceConfidence.CONFLICTING,p.modelConfidence); assertEquals("",p.model);
        assertNotEquals(DeviceConfidence.CORROBORATED,p.confidence);
    }
    @Test public void protocolRoutingProtectsEncryptedAndPrintingServices() {
        assertTrue(DeviceIdentifier.isTlsEndpoint(443,""));
        assertTrue(DeviceIdentifier.isTlsEndpoint(1234,"_ipps._tcp."));
        assertFalse(DeviceIdentifier.isHttpEndpoint(443,"_https._tcp."));
        assertFalse(DeviceIdentifier.isIppEndpoint(631,"_ipps._tcp."));
        assertTrue(DeviceIdentifier.isRtspEndpoint(554,""));
        assertTrue(DeviceIdentifier.isRtspEndpoint(1234,"_rtsp._tcp."));
        assertFalse(DeviceIdentifier.isRtspEndpoint(554,"_https._tcp."));
        assertTrue(DeviceIdentifier.probePriority(631,"")<DeviceIdentifier.probePriority(21,""));
    }
    @Test public void rtspOptionsDoesNotStartStreamingAndValidatesSequence() throws Exception {
        for(String sequence:new String[]{"1","2"}) try(ServerSocket server=new ServerSocket(0,1,InetAddress.getLoopbackAddress())) {
            ExecutorService worker=Executors.newSingleThreadExecutor();
            Future<String> request=worker.submit(()-> {
                try(Socket socket=server.accept()) {
                    socket.setSoTimeout(2000); BufferedReader in=new BufferedReader(new InputStreamReader(socket.getInputStream(),StandardCharsets.US_ASCII));
                    String first=in.readLine(); while(!in.readLine().isEmpty()) { }
                    socket.getOutputStream().write(("RTSP/1.0 200 OK\r\nCSeq: "+sequence+"\r\nServer: Example\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    return first;
                }
            });
            try {
                DeviceEvidence e=new DeviceEvidence(Collections.singleton("127.0.0.1"));
                new DeviceIdentifier(new ScanPlan(IP,"554",200),e).rtsp("127.0.0.1",server.getLocalPort());
                assertEquals("OPTIONS * RTSP/1.0",request.get(3,TimeUnit.SECONDS));
                assertEquals(sequence.equals("1")?"_rtsp._tcp.":"",DeviceEvidence.first(e.observations("127.0.0.1"),"serviceType"));
            } finally { worker.shutdownNow(); }
        }
    }
    @Test public void smbNegotiationIsBoundedAndDoesNotAuthenticate() {
        byte[] request=Smb.request(); java.nio.ByteBuffer q=java.nio.ByteBuffer.wrap(request).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        assertEquals(112,request.length); assertEquals(108,request[3]&255);
        assertEquals(0,q.getShort(16)); assertEquals(36,q.getShort(68));assertEquals(4,q.getShort(70));
        byte[] reply=new byte[132]; reply[3]=(byte)128;
        java.nio.ByteBuffer b=java.nio.ByteBuffer.wrap(reply).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        b.putInt(4,0x424d53fe);b.putShort(8,(short)64);b.putInt(20,1);b.putShort(68,(short)65);b.putShort(70,(short)3);b.putShort(72,(short)0x0302);
        assertEquals("3.0.2",Smb.parse(reply).get("smbNegotiatedDialect"));assertEquals("Required",Smb.parse(reply).get("smbSigning"));
        for(int i=0;i<reply.length;i++) assertTrue(Smb.parse(Arrays.copyOf(reply,i)).isEmpty());
        b.putLong(28,99);assertTrue(Smb.parse(reply).isEmpty());b.putLong(28,0);
        b.putShort(72,(short)0x0311);assertTrue(Smb.parse(reply).isEmpty());
        assertFalse(DeviceIdentifier.isSmbEndpoint(445,"_https._tcp."));
    }
    @Test public void multipleServiceRolesDoNotForceOneHardwareType() {
        DeviceEvidence e=new DeviceEvidence(Collections.singleton(IP));
        e.add(IP,"mDNS","serviceType","_ipp._tcp.");e.add(IP,"mDNS","serviceType","_googlecast._tcp.");
        DeviceProfile profile=new DeviceProfile(e.observations(IP));
        assertEquals("Multiple advertised roles",profile.type);assertTrue(profile.typeConfidence == DeviceConfidence.MULTIPLE_ROLES);
    }
    @Test public void tlsFailureIsVisibleWithoutPlaintextFallback() throws Exception {
        try(ServerSocket server=new ServerSocket(0,1,InetAddress.getLoopbackAddress())) {
            ExecutorService worker=Executors.newSingleThreadExecutor();
            Future<Integer> first=worker.submit(()-> {
                try(Socket socket=server.accept()) {
                    socket.setSoTimeout(2000); int marker=socket.getInputStream().read();
                    socket.getOutputStream().write("HTTP/1.0 200 OK\r\n\r\n".getBytes(StandardCharsets.US_ASCII));return marker;
                }
            });
            try {
                DeviceEvidence e=new DeviceEvidence(Collections.singleton("127.0.0.1"));
                new DeviceIdentifier(new ScanPlan(IP,"443",200),e).tls("127.0.0.1",server.getLocalPort(),"_https._tcp.");
                assertEquals(22,(int)first.get(3,TimeUnit.SECONDS)); // TLS handshake record, never GET.
                assertEquals("",DeviceEvidence.first(e.observations("127.0.0.1"),"tlsValidation","httpTitle"));
                assertTrue(DeviceEvidence.first(e.observations("127.0.0.1"),"probeStatus").contains("handshake failed"));
            } finally {worker.shutdownNow();}
        }
    }
    @Test public void tcpCompletionDoesNotHidePartialIdentification() throws Exception {
        JSONObject report=new JSONObject().put("completedChecks",2).put("plannedChecks",2);
        assertTrue(ScanReport.completion(report,"wifi-a",false,true,false));
        assertTrue(report.getBoolean("tcpScanComplete"));assertFalse(report.getBoolean("identificationComplete"));
        assertEquals("partial",report.getString("identificationStatus"));
        assertFalse(ScanReport.completion(report,"wifi-a",false,false,false));
        assertTrue(ScanReport.completion(report,"wifi-a",true,false,false));
        report.put("completedChecks",1);
        assertTrue(ScanReport.completion(report,"wifi-a",false,false,false));assertFalse(report.getBoolean("tcpScanComplete"));
        assertTrue(ScanReport.completion(report,"wifi-a",false,false,true));assertEquals("cancelled",report.getString("identificationStatus"));
    }
    private JSONObject report(String network) throws JSONException {
        return new JSONObject().put("target",IP).put("finishedAtEpochMs",1).put("completedChecks",1)
            .put("networkScope",network).put("identificationComplete",true).put("checks",new JSONArray()).put("devices",new JSONArray());
    }
    @Test public void historySeparatesNetworksSettingsAndRejectsPartialIdentity() throws Exception {
        File dir=java.nio.file.Files.createTempDirectory("analysis-history").toFile(); File file=new File(dir,"history.json");
        try {
            ScanHistory h=new ScanHistory(file); ScanPlan plan=new ScanPlan(IP,"80",200);
            assertTrue(h.save(report("wifi-a"),plan).startsWith("First"));
            assertTrue(h.save(report("wifi-b"),plan).startsWith("First"));
            assertTrue(h.save(report("wifi-a"),plan).startsWith("No responder"));
            assertTrue(h.save(report("wifi-a"),new ScanPlan(IP,"80",300)).startsWith("First"));
            int size=h.load().length();
            assertTrue(h.save(report(""),plan).contains("unavailable"));
            assertTrue(h.save(report("wifi-a").put("identificationComplete",false),plan).contains("partial"));
            assertTrue(h.save(report("wifi-a").put("networkChanged",true),plan).contains("changed"));
            assertEquals(size,h.load().length());
        } finally { file.delete();dir.delete(); }
    }
    @Test public void findingsRequireEvidenceRatherThanPortNumbers() {
        assertTrue(AnalysisFindings.describe(Collections.emptyList()).isEmpty());
        DeviceEvidence e=new DeviceEvidence(Collections.singleton(IP));
        e.add(IP,"Banner tcp/22","banner","SSH-2.0-example");
        assertEquals(1,AnalysisFindings.describe(e.observations(IP)).size());
        assertTrue(AnalysisFindings.describe(e.observations(IP)).get(0).contains("does not confirm"));
    }
}
