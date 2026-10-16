package com.netmap.android;

import java.util.*;
import org.json.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class LargeScanReportTest {
    @Test public void fullProgressAndPackedDetailsRemainSeparateFromDisplayChecks() throws Exception {
        ScanPlan plan = new ScanPlan("192.168.0.0/31", "80,443", 200);
        PackedScanResults results = new PackedScanResults(plan);
        for(String host : plan.hosts) for(int port : plan.ports)
            results.add(new TcpScanner.Result(host, port, port==80 ? TcpScanner.State.CLOSED : TcpScanner.State.NO_RESPONSE, 1, 200));
        Map<String,List<DeviceEvidence.Observation>> identified = new HashMap<>();
        for (String host : plan.hosts) identified.put(host, new ArrayList<>());
        JSONObject json = new JSONObject(ScanReport.json(results, plan, "192.168.0.0/31", false, 1L,
                identified, new ArrayList<>(), new ArrayList<>()));
        assertEquals(6,json.getInt("schemaVersion"));
        assertEquals(4,json.getInt("completedChecks"));
        assertEquals(2,json.getJSONArray("checks").length());
        assertEquals(2,json.getJSONObject("packedChecks").getJSONArray("hosts").length());
        assertFalse(ScanReport.completion(json,"test-network",false,false,false));
        assertTrue(json.getBoolean("tcpScanComplete"));
        assertEquals(2, new ReportPresentation(json).devices.size());
        assertTrue(new ReportPresentation(json).fullText().contains("4 / 4"));
    }

    @Test public void cancelledPackedResultsCannotBecomeACompletedScan() throws Exception {
        ScanPlan plan = new ScanPlan("192.168.0.0/31", "80,443", 200);
        PackedScanResults results = new PackedScanResults(plan);
        results.add(new TcpScanner.Result("192.168.0.0",80,TcpScanner.State.CLOSED,1,200));
        JSONObject json = new JSONObject(ScanReport.json(results, plan, "192.168.0.0/31", true, 1L,
                new HashMap<>(), new ArrayList<>(), new ArrayList<>()));
        assertEquals(1,json.getInt("completedChecks"));
        assertTrue(ScanReport.completion(json,"test-network",false,false,true));
        assertFalse(json.getBoolean("tcpScanComplete"));
    }
}
