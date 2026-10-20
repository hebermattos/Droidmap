package com.netmap.android;

import static org.junit.Assert.*;
import java.util.*;
import org.json.*;
import org.junit.Test;

public class MacReportTest {
    @Test public void wifiMacIdentificationAppearsInPreviewJsonAndTextWithoutOverwritingProtocolIdentity() throws Exception {
        MacVendorCatalog.load(getClass().getClassLoader().getResourceAsStream("mac-vendors.tsv"));
        String ip="192.168.0.109";
        DeviceEvidence evidence=new DeviceEvidence(List.of(ip));
        evidence.add(ip,"IPv4 neighbor","neighborMac","D0:03:DF:A8:3D:7F");
        evidence.add(ip,"NetBIOS","reportedMac","CE:24:04:6A:12:34");
        evidence.add(ip,"HTTP","manufacturer","Reported maker");
        ScanPlan plan=new ScanPlan(ip,"80",200);
        List<TcpScanner.Result> checks=List.of(new TcpScanner.Result(ip,80,TcpScanner.State.OPEN));
        for(String json:List.of(ScanReport.json(checks,plan,ip,false,1,evidence.snapshot(),List.of(),List.of()),
                ScanReport.preview(ip,checks,List.of(),evidence.snapshot()))) {
            JSONObject device=new JSONObject(json).getJSONArray("devices").getJSONObject(0);
            JSONArray macs=device.getJSONArray("macAddresses");
            JSONObject global=macs.getJSONObject(0).getJSONObject("macIdentification");
            assertTrue(global.getString("vendor").contains("Samsung"));
            assertEquals("D003DF",global.getString("prefix"));
            assertEquals(24,global.getInt("prefixBits"));
            assertEquals("IPv4 neighbor",macs.getJSONObject(0).getString("source"));
            JSONObject local=macs.getJSONObject(1).getJSONObject("macIdentification");
            assertEquals("",local.getString("vendor"));
            assertEquals("Unavailable for local address",local.getString("status"));
            assertEquals("Reported maker",device.getString("reportedManufacturer"));
            String text=new ReportPresentation(new JSONObject(json)).fullText();
            assertTrue(text.contains("Samsung"));
            assertTrue(text.contains("Unavailable for local address"));
            assertTrue(text.contains("Reported maker"));
        }
        assertTrue(ScanReport.describe(checks,plan,false,evidence.snapshot(),List.of(),0,0).contains("Samsung"));
        JSONObject missing=ScanReport.device(ip,List.of());
        assertEquals(0,missing.getJSONArray("macAddresses").length());
        // Old reports remain readable without invented manufacturer data.
        JSONObject legacy=new JSONObject().put("devices",new JSONArray().put(new JSONObject().put("ip",ip)
                .put("macAddresses",new JSONArray().put(new JSONObject().put("address","D0:03:DF:A8:3D:7F")))));
        assertFalse(new ReportPresentation(legacy).fullText().contains("Samsung"));
    }

    @Test public void previewAndFinalReportRetainMacSourcesWithoutChangingReportedMac() throws Exception {
        String ip = "192.168.0.109";
        DeviceEvidence evidence = new DeviceEvidence(List.of(ip));
        evidence.add(ip, "IPv4 neighbor", "neighborMac", "CE:24:04:6A:12:34");
        evidence.add(ip, "NetBIOS", "reportedMac", "00:11:22:33:44:55");
        ScanPlan plan = new ScanPlan(ip, "80", 200);
        String report = ScanReport.json(Collections.emptyList(), plan, ip, false, 1,
                evidence.snapshot(), Collections.emptyList(), Collections.emptyList());
        String preview = ScanReport.preview(ip, Collections.emptyList(), Collections.emptyList(), evidence.snapshot());
        for (String json : List.of(report, preview)) {
            JSONObject device = new JSONObject(json).getJSONArray("devices").getJSONObject(0);
            assertEquals("00:11:22:33:44:55", device.getString("reportedMac"));
            JSONArray macs = device.getJSONArray("macAddresses");
            assertEquals(2, macs.length());
            assertEquals("IPv4 neighbor", macs.getJSONObject(0).getString("source"));
            assertTrue(macs.getJSONObject(0).getString("kind").contains("may be randomized"));
        }
        String text = ScanReport.describe(Collections.emptyList(), plan, false, evidence.snapshot(),
                Collections.emptyList(), 0, 0);
        assertTrue(text.contains("MAC [IPv4 neighbor]: CE:24:04:6A:12:34"));
        assertTrue(text.contains("MAC [NetBIOS]: 00:11:22:33:44:55"));
    }
}
