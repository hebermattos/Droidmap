package com.netmap.android;

import org.json.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ReportPresentationTest {
    private JSONObject observation(String source,String field,String value)throws Exception {
        return new JSONObject().put("source",source).put("field",field).put("value",value);
    }
    private JSONObject report(JSONArray evidence)throws Exception {
        return new JSONObject().put("target","192.168.0.0/24").put("devices",new JSONArray().put(
            new JSONObject().put("ip","192.168.0.1").put("probableType","Unknown").put("evidence",evidence)));
    }
    @Test public void distinguishesCompletedFailedCancelledAndMissingAssessments()throws Exception {
        assertEquals(ReportPresentation.Status.NOT_RUN,ReportPresentation.status(""));
        assertEquals(ReportPresentation.Status.RUNNING,ReportPresentation.status("Running service detection"));
        assertEquals(ReportPresentation.Status.FAILED,ReportPresentation.status("Failed: Nmap exited with code 1"));
        assertEquals(ReportPresentation.Status.CANCELLED,ReportPresentation.status("Failed: Nmap cancelled"));
        assertEquals(ReportPresentation.Status.UNKNOWN,ReportPresentation.status("legacy result"));
        ReportPresentation absent=new ReportPresentation(report(new JSONArray()));
        assertEquals("Not executed",absent.devices.get(0).vulnerabilitySummary());
        assertTrue(absent.fullText().contains("No vulnerability assessment completed"));
        JSONArray evidence=new JSONArray().put(observation("Nmap","scanStatus","Completed"))
            .put(observation("Nmap vulnerabilities","scanStatus","Command finished on 1 target port(s); see script results."));
        ReportPresentation completed=new ReportPresentation(report(evidence));
        assertTrue(completed.devices.get(0).vulnerabilitySummary().startsWith("No vulnerability alerts reported"));
        assertTrue(completed.fullText().contains("does not prove absence of vulnerabilities"));
    }
    @Test public void deduplicatesPortsAndPreservesActualServiceVersions()throws Exception {
        JSONArray evidence=new JSONArray().put(observation("Nmap","openPort","80/tcp"))
            .put(observation("Nmap","openPort","443/tcp"))
            .put(observation("Nmap","openPort","65536/tcp"))
            .put(observation("Nmap service 80","serviceName","http"))
            .put(observation("Nmap service 80","banner","nginx 1.26"));
        JSONObject json=report(evidence);
        JSONObject open=new JSONObject().put("ip","192.168.0.1").put("port",80).put("state","OPEN");
        json.put("checks",new JSONArray().put(open));json.put("advertisedEndpointChecks",new JSONArray().put(open));
        ReportPresentation model=new ReportPresentation(json);
        assertEquals(2,model.devices.get(0).ports.size());
        assertEquals("http",model.devices.get(0).services.get(80));
        assertTrue(model.fullText().contains("80/TCP · http · nginx 1.26"));
        assertTrue(model.fullText().contains("443/TCP · Not identified · Version not identified"));
        assertTrue(model.summary().contains("Open TCP endpoints: 2"));
    }
    @Test public void negativeAndInconclusiveScriptResultsAreNotConfirmedVulnerabilities() {
        ReportPresentation.Finding negative=new ReportPresentation.Finding("ssl-test","port 443","State: NOT VULNERABLE");
        assertFalse(negative.alert);assertFalse(negative.assessment.contains("confirmation required"));
        ReportPresentation.Finding failed=new ReportPresentation.Finding("ssl-test","port 443","ERROR: could not complete check");
        assertEquals("Inconclusive check",failed.assessment);assertFalse(failed.alert);
        ReportPresentation.Finding explicit=new ReportPresentation.Finding("ssl-test","port 443","State: VULNERABLE Evidence: test");
        assertTrue(explicit.alert);assertEquals("Reported vulnerable — confirmation required",explicit.assessment);
        assertTrue(explicit.action.contains("If confirmed"));
        ReportPresentation.Finding likely=new ReportPresentation.Finding("ssl-test","port 443","LIKELY VULNERABLE");
        assertEquals("Alert — review required",likely.assessment);
    }
    @Test public void filtersDoNotDiscardInventoryOrTreatOpenPortsAsAlerts()throws Exception {
        JSONObject json=report(new JSONArray().put(observation("Nmap","scanStatus","Failed: could not locate nse_main.lua")));
        ReportPresentation.Device device=new ReportPresentation(json).devices.get(0);
        assertTrue(device.matches(ReportPresentation.Filter.FAILURES));assertFalse(device.matches(ReportPresentation.Filter.ALERTS));
        assertFalse(device.matches(ReportPresentation.Filter.OPEN));assertTrue(device.matches(ReportPresentation.Filter.ALL));
        assertEquals(1,json.getJSONArray("devices").length());
        assertEquals("Nmap could not start: a required script file is missing.",ReportPresentation.friendlyError(device.serviceMessage));
    }
    @Test public void fullReportUsesRealLineBreaksAndMarksPartialAndCancelledResults()throws Exception {
        JSONObject json=report(new JSONArray());json.put("identificationComplete",false);
        ReportPresentation model=new ReportPresentation(json);
        assertEquals("Completed with partial results",model.scanStatus());
        assertTrue(model.fullText().startsWith("SCAN SUMMARY\nCompleted with partial results\n"));
        assertFalse(model.fullText().contains("\\n"));
        json.put("cancelled",true);assertEquals("Cancelled — partial results",new ReportPresentation(json).scanStatus());
        json.put("cancelled",false).put("partial",true);assertEquals("In progress — partial results",new ReportPresentation(json).scanStatus());
    }
    @Test public void protocolWarningsDoNotImplyNmapWasExecuted()throws Exception {
        JSONObject json=report(new JSONArray());
        json.getJSONArray("devices").getJSONObject(0).put("analysisFindings",new JSONArray().put("Review: TLS handshake failed. This does not establish a vulnerability."));
        ReportPresentation.Device device=new ReportPresentation(json).devices.get(0);
        assertTrue(device.hasAlerts());
        assertEquals(ReportPresentation.Status.NOT_RUN,device.vulnerabilityStatus);
    }
    @Test public void oldEvidenceWithoutExecutionStatusRemainsUnknown()throws Exception {
        ReportPresentation model=new ReportPresentation(report(new JSONArray().put(observation("Nmap service 80","serviceName","http"))));
        assertEquals(ReportPresentation.Status.UNKNOWN,model.devices.get(0).serviceStatus);
    }
}
