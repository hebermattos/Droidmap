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
        assertTrue(model.fullText().contains("443/TCP · Service not identified"));
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
        assertTrue(device.ports.isEmpty());assertTrue(device.matches(ReportPresentation.Filter.ALL));
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
    @Test public void nucleiFindingsAreIncludedInVulnerabilitySummary()throws Exception {
        JSONArray evidence=new JSONArray()
            .put(observation("Nmap","openPort","80/tcp"))
            .put(observation("Nmap service 80","serviceName","http"))
            .put(observation("Nuclei","finding:80:Exposed Git HEAD metadata [medium]",
                    "VULNERABLE — A public .git/HEAD file may expose repository metadata."));
        ReportPresentation.Device device=new ReportPresentation(report(evidence)).devices.get(0);
        assertTrue(device.hasAlerts());
        assertEquals("Exposed Git HEAD metadata [medium]",device.findings.get(0).title);
        assertEquals("port 80",device.findings.get(0).scope);
        assertEquals("Nuclei",device.findings.get(0).source);
        assertTrue(device.vulnerabilitySummary().startsWith("Alerts reported"));
        assertEquals("http",device.services.get(80));
    }
    @Test public void nucleiInformationalFindingAndEndpointDiagnosticsRemainAvailable()throws Exception {
        JSONArray evidence=new JSONArray()
            .put(observation("Nuclei","endpoint:8080","http • completed • 3 configured templates"))
            .put(observation("Nuclei","finding:8080:Missing HTTP security headers [info]",
                    "VULNERABLE — Security headers are missing"));
        ReportPresentation.Device device=new ReportPresentation(report(evidence)).devices.get(0);
        assertEquals(1,device.findings.size());
        assertEquals("port 8080",device.findings.get(0).scope);
        assertTrue(device.evidence.stream().anyMatch(x->
                x.optString("field").equals("endpoint:8080")));
    }
    @Test public void oldEvidenceWithoutExecutionStatusRemainsUnknown()throws Exception {
        ReportPresentation model=new ReportPresentation(report(new JSONArray().put(observation("Nmap service 80","serviceName","http"))));
        assertEquals(ReportPresentation.Status.UNKNOWN,model.devices.get(0).serviceStatus);
    }
    @Test public void webLinksRequireIdentifiedHttpAndOpenPorts()throws Exception {
        JSONArray evidence=new JSONArray()
            .put(observation("Nmap","openPort","8081/tcp"))
            .put(observation("Nmap service 8081","serviceName","http"))
            .put(observation("HTTP tcp/8081","webUrl","http://untrusted.example/"))
            .put(observation("HTTP tcp/1234","httpTitle","Closed endpoint"))
            .put(observation("HTTP tcp/8080","probeStatus","No valid HTTP reply"))
            .put(observation("Nmap","openPort","8080/tcp"))
            .put(observation("Nmap","openPort","22/tcp"))
            .put(observation("Nmap service 22","serviceName","ssh"));
        ReportPresentation model=new ReportPresentation(report(evidence));
        assertEquals(java.util.Set.of("http://192.168.0.1:8081/"),model.devices.get(0).webLinks());
        assertTrue(model.fullText().contains("Web interface: http://192.168.0.1:8081/"));
    }
    @Test public void webLinksSupportHttpsAndIpv6WithScope()throws Exception {
        JSONArray evidence=new JSONArray().put(observation("Nmap","openPort","443/tcp"))
            .put(observation("Nmap service 443","serviceName","https"))
            .put(observation("Nmap","openPort","8443/tcp"))
            .put(observation("HTTPS tcp/8443","server","nginx"));
        JSONObject json=report(evidence);
        json.getJSONArray("devices").getJSONObject(0).put("ip","fe80::1%wlan0");
        assertEquals(java.util.Set.of("https://[fe80::1%25wlan0]/","https://[fe80::1%25wlan0]:8443/"),
            new ReportPresentation(json).devices.get(0).webLinks());
        json.getJSONArray("devices").getJSONObject(0).put("ip","fd00::1");
        assertTrue(new ReportPresentation(json).devices.get(0).webLinks().contains("https://[fd00::1]/"));
        json.getJSONArray("devices").getJSONObject(0).put("ip","evil.example/path");
        assertTrue(new ReportPresentation(json).devices.get(0).webLinks().isEmpty());
    }
    @Test public void successfulHttpReplyCreatesLinkWithoutNmap()throws Exception {
        JSONObject json=report(new JSONArray().put(observation("HTTP tcp/80","webUrl","ignored")));
        json.put("checks",new JSONArray().put(new JSONObject().put("ip","192.168.0.1").put("port",80).put("state","OPEN")));
        assertEquals(java.util.Set.of("http://192.168.0.1/"),new ReportPresentation(json).devices.get(0).webLinks());
    }
    @Test public void nucleiExecutionStatusIsIndependentAndFailuresAreFilterable()throws Exception {
        JSONArray evidence=new JSONArray()
                .put(observation("Nuclei","endpoint:80","http • completed • 3 configured templates"))
                .put(observation("Nuclei","endpoint:443","https • incomplete • 3 configured templates"));
        ReportPresentation model=new ReportPresentation(report(evidence));
        ReportPresentation.Device device=model.devices.get(0);
        assertEquals(ReportPresentation.Status.FAILED,device.nucleiStatus);
        assertEquals(ReportPresentation.Status.NOT_RUN,device.vulnerabilityStatus);
        assertTrue(device.matches(ReportPresentation.Filter.FAILURES));
        assertTrue(model.summary().contains("Devices with tool failures: 1"));
        assertTrue(model.scanDetails().contains("Nuclei: 1 failed"));
        device=new ReportPresentation(report(new JSONArray().put(observation("Nuclei","endpoint:80","http • cancelled • 3 configured templates")))).devices.get(0);
        assertEquals(ReportPresentation.Status.CANCELLED,device.nucleiStatus);
        assertFalse(device.hasFailures());
    }
    @Test public void successfulNucleiWithoutMatchesIsAnAssessmentAndLegacyFindingsAreUnknown()throws Exception {
        ReportPresentation model=new ReportPresentation(report(new JSONArray().put(
                observation("Nuclei","endpoint:80","http • completed • 3 configured templates"))));
        assertEquals(ReportPresentation.Status.COMPLETED,model.devices.get(0).nucleiStatus);
        assertTrue(model.devices.get(0).vulnerabilitySummary().startsWith("No vulnerability alerts reported"));
        assertFalse(model.fullText().contains("No vulnerability assessment completed"));
        model=new ReportPresentation(report(new JSONArray().put(observation("Nuclei","finding:80:Test","VULNERABLE — evidence"))));
        assertEquals(ReportPresentation.Status.UNKNOWN,model.devices.get(0).nucleiStatus);
        assertEquals(ReportPresentation.Status.NOT_RUN,model.devices.get(0).vulnerabilityStatus);
    }
    @Test public void fullReportKeepsNucleiEvidenceOnceAndUsesCorrectTool()throws Exception {
        ReportPresentation model=new ReportPresentation(report(new JSONArray()
                .put(observation("Nuclei","endpoint:80","http • completed • 3 configured templates"))
                .put(observation("Nuclei","finding:80:Test","VULNERABLE — unique-evidence"))));
        String text=model.fullText();
        assertTrue(text.contains("Nuclei · Test · port 80"));
        assertEquals(1,text.split("unique-evidence",-1).length-1);
        assertTrue(text.contains("endpoint:80: http • completed"));
    }
    @Test public void compactDetailsOmitRepeatedTotalsAndPortRowsOmitMissingVersions()throws Exception {
        ReportPresentation model=new ReportPresentation(report(new JSONArray()
                .put(observation("Nmap","openPort","80/tcp"))
                .put(observation("Nmap service 80","serviceName","http"))));
        assertFalse(model.scanDetails().contains("Devices:"));
        assertFalse(model.scanDetails().contains("Open TCP endpoints:"));
        assertTrue(model.scanDetails().startsWith("Target:"));
        assertEquals("80/TCP · http",model.devices.get(0).portLine(80));
    }
    @Test public void additionalMetadataExcludesDedicatedToolAndIdentityEvidence()throws Exception {
        assertFalse(ReportPresentation.Device.additionalEvidence(observation("Nuclei","finding:80:Test","value")));
        assertFalse(ReportPresentation.Device.additionalEvidence(observation("Nuclei","endpoint:80","value")));
        assertFalse(ReportPresentation.Device.additionalEvidence(observation("Nmap service 80","banner","value")));
        assertFalse(ReportPresentation.Device.additionalEvidence(observation("UPnP","manufacturer","value")));
        assertTrue(ReportPresentation.Device.identityEvidence(observation("UPnP","manufacturer","value")));
        assertTrue(ReportPresentation.Device.additionalEvidence(observation("HTTP tcp/80","server","value")));
    }

}
