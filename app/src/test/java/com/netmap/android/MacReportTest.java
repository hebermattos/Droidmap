package com.netmap.android;

import static org.junit.Assert.*;
import java.util.*;
import org.json.*;
import org.junit.Test;

public class MacReportTest {
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
