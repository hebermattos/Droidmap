package com.netmap.android;

import org.json.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class BluetoothPresentationTest {
    @Test public void decodersAndSummaryAreIncludedWithoutLosingRawData() throws Exception {
        String raw="000000000243357CE26133010A0000E8010000F7B397BDA85EBD26";
        JSONObject row=new JSONObject().put("address","43:35:7C:CD:14:CD").put("name","CAR APP")
                .put("ble",true).put("classic",true).put("observations",4).put("rssi",-99).put("connectable",true)
                .put("manufacturerData",new JSONObject().put("0x05D6",new JSONObject().put("hex",raw)));
        BluetoothPresentation.enrich(row);
        assertEquals(raw,row.getJSONObject("manufacturerData").getJSONObject("0x05D6").getString("hex"));
        assertEquals("inferred",row.getJSONArray("decodedAdvertisements").getJSONObject(0).getString("confidence"));
        assertTrue(row.getString("summary").contains("BLE + Classic"));
        assertTrue(row.getString("summary").contains("Candidate battery slot 1: 10% [inferred]"));
        assertFalse(row.getString("summary").contains("10% (GATT reported)"));
        assertTrue(BluetoothPresentation.decodedDetails(row).contains("Undecoded bytes:"));
        assertEquals(row.getString("summary"),new JSONObject(row.toString()).getString("summary"));
    }
    @Test public void failedAndCustomReadsDoNotBecomeReportedDeviceInformation() throws Exception {
        JSONObject row=new JSONObject().put("address","a").put("observations",1).put("ble",true);
        JSONArray chars=new JSONArray().put(new JSONObject().put("uuid","00002a24-0000-1000-8000-00805f9b34fb")
                .put("value","stale model").put("readStatus",5));
        row.put("gattServices",new JSONArray().put(new JSONObject().put("uuid","0000180a-0000-1000-8000-00805f9b34fb").put("characteristics",chars)));
        assertFalse(BluetoothPresentation.summary(row).contains("stale model"));
        chars.getJSONObject(0).put("readStatus",0).put("value","Valid Model");
        assertTrue(BluetoothPresentation.summary(row).contains("Valid Model (GATT reported)"));
        row.getJSONArray("gattServices").getJSONObject(0).put("uuid","vendor-service");
        assertFalse(BluetoothPresentation.summary(row).contains("Valid Model"));
    }
    @Test public void livePhaseAndRetryHistoryAreReadable() throws Exception {
        JSONObject row=new JSONObject().put("address","a").put("inspectionStatus","Running")
                .put("connectionAttempts",new JSONArray().put(new JSONObject().put("status","failed")).put(new JSONObject().put("status","running")))
                .put("inspectionStages",new JSONObject().put("connection",new JSONObject().put("status","running").put("detail","Connecting attempt 2/2")));
        String summary=BluetoothPresentation.summary(row);
        assertTrue(summary.contains("Connecting attempt 2/2"));
        assertTrue(summary.contains("Connection attempts: 2/2"));
        row.getJSONObject("inspectionStages").getJSONObject("connection").put("status","cancelled");
        row.put("inspectionStatus","Stopped");
        assertFalse(BluetoothPresentation.summary(row).contains("Connecting attempt"));
        assertTrue(BluetoothPresentation.summary(row).contains("Stopped"));
    }
}
