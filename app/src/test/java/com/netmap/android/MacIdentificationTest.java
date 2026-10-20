package com.netmap.android;

import org.json.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class MacIdentificationTest {
    @Test public void identityEvidenceRemainsSeparateInSummaryAndExport() throws Exception {
        MacVendorCatalog.load(getClass().getClassLoader().getResourceAsStream("mac-vendors.tsv"));
        JSONObject row = new JSONObject().put("address", "D0:03:DF:A8:3D:7F").put("ble", true)
                .put("addressType", "public").put("name", "Announced name")
                .put("manufacturerData", new JSONObject().put("0x0006", new JSONObject().put("hex", "01092022")))
                .put("gattServices", new JSONArray().put(new JSONObject().put("uuid", "0000180a-0000-1000-8000-00805f9b34fb")
                        .put("characteristics", new JSONArray().put(new JSONObject().put("uuid", "00002a29-0000-1000-8000-00805f9b34fb")
                                .put("value", "Reported maker").put("readStatus", 0)))));
        BluetoothPresentation.enrich(row);
        assertTrue(row.getString("summary").contains("Samsung"));
        assertTrue(row.getString("summary").contains("Reported maker (GATT reported)"));
        assertTrue(row.getString("summary").contains("0x0006"));
        assertEquals("D003DF", row.getJSONObject("macIdentification").getString("prefix"));
        assertEquals(24, row.getJSONObject("macIdentification").getInt("prefixBits"));
        JSONObject exported = new JSONObject(row.toString());
        assertTrue(exported.getJSONObject("macIdentification").getString("vendor").contains("Samsung"));
        assertEquals("01092022", exported.getJSONObject("manufacturerData").getJSONObject("0x0006").getString("hex"));
        row.put("addressType", "random");
        BluetoothPresentation.enrich(row);
        assertEquals("", row.getJSONObject("macIdentification").getString("vendor"));
        assertFalse(row.getString("summary").contains("Samsung"));
        assertTrue(row.getString("summary").contains("Random static"));
        row.remove("addressType");
        BluetoothPresentation.enrich(row);
        assertTrue(row.getJSONObject("macIdentification").getString("status").startsWith("Candidate"));
    }
}
