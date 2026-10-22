package com.netmap.android;

import org.json.*;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class HttpxTest {
    private final String ip="192.168.0.1",url="http://192.168.0.1:8080/";
    private DeviceEvidence evidence(){return new DeviceEvidence(Collections.singletonList(ip));}
    @Test public void webAdmissionNeedsEvidenceAndPreservesIpv6Scope() {
        DeviceEvidence e=evidence();
        assertEquals("",WebEndpoints.scheme(Collections.emptyList(),443));
        e.add(ip,"Nmap service 8080","serviceName","http");
        assertEquals("",WebEndpoints.scheme(e.snapshot().get(ip),8080));
        e.add(ip,"Nmap","openPort","8080/tcp");
        assertEquals("http",WebEndpoints.scheme(e.snapshot().get(ip),8080));
        assertEquals("",WebEndpoints.scheme(e.snapshot().get(ip),80));
        assertEquals("https://[fe80::1%25wlan0]:443/",WebEndpoints.url("https","fe80::1%wlan0",443));
    }
    @Test public void parserScopesResultsAndDoesNotVisitRedirectsOrTreat401AsFailure() throws Exception {
        DeviceEvidence e=evidence();
        String row=new JSONObject().put("url",url).put("status_code",401).put("title","Router Login")
                .put("location","https://example.com/").put("webserver","nginx")
                .put("tech",new JSONArray().put("nginx")).put("body","secret raw body").toString();
        assertTrue(HttpxResult.record(row,url,ip,8080,e));
        String values=SessionAnalyses.toolEvidence("httpx",e.snapshot().get(ip)).toString();
        assertTrue(values.contains("Router Login"));assertTrue(values.contains("technologyEstimate"));
        assertFalse(values.contains("secret raw body"));
        assertFalse(HttpxResult.record(row,"http://192.168.0.2:8080/",ip,8080,e));
        assertFalse(HttpxResult.record(new JSONObject(row).put("failed",true).toString(),url,ip,8080,e));
        assertFalse(HttpxResult.record(new JSONObject(row).put("status_code",0).toString(),url,ip,8080,e));
        assertFalse(HttpxResult.record("x".repeat(HttpxResult.MAX_LINE+1),url,ip,8080,e));
    }
    @Test public void httpxSessionStatusEvidenceAndPanelAreIndependentOfNuclei() throws Exception {
        DeviceEvidence e=evidence();e.add(ip,"HTTPX tcp/8080","scanStatus","completed");
        List<DeviceEvidence.Observation> items=e.snapshot().get(ip);
        assertEquals("completed",SessionAnalyses.status("httpx",items,false));
        assertEquals("cancelled",SessionAnalyses.status("httpx",items,true));
        assertEquals("failed",SessionAnalyses.status("httpx",Collections.emptyList(),false));
        assertEquals(1,SessionAnalyses.toolEvidence("httpx",items).length());
        assertEquals(0,SessionAnalyses.toolEvidence("nuclei",items).length());
        JSONObject panel=new JSONObject().put("tool","httpx").put("analysisRuns",new JSONArray());
        assertTrue(AnalysisPresentation.toolPanel(panel));
    }
    @Test public void rerunReplacesOnlyHttpxAndFullReportRetainsItsMetadata() throws Exception {
        JSONObject baseline=new JSONObject().put("startedAtEpochMs",1).put("target",ip).put("networkScope","wifi")
                .put("devices",new JSONArray().put(new JSONObject().put("ip",ip).put("evidence",new JSONArray())));
        JSONObject attempt=new JSONObject().put("tool","httpx").put("ip",ip).put("port",8080)
                .put("status","completed").put("finishedAtEpochMs",2);
        DeviceEvidence e=evidence();e.add(ip,"HTTPX tcp/8080","httpTitle","Old title");
        attempt.put("evidence",SessionAnalyses.toolEvidence("httpx",e.snapshot().get(ip)));
        JSONObject session=SessionAnalyses.append(baseline,null,attempt);
        JSONObject nuclei=new JSONObject().put("tool","nuclei").put("ip",ip).put("port",8080)
                .put("status","failed").put("finishedAtEpochMs",3).put("evidence",new JSONArray());
        session=SessionAnalyses.append(baseline,session,nuclei);
        e=evidence();e.add(ip,"HTTPX tcp/8080","httpTitle","New title");
        attempt.put("evidence",SessionAnalyses.toolEvidence("httpx",e.snapshot().get(ip)));
        session=SessionAnalyses.append(baseline,session,attempt);
        assertEquals(2,SessionAnalyses.runs(session).length());
        assertEquals("failed",SessionAnalyses.endpointStatus(session,"nuclei",ip,8080));
        String full=new ReportPresentation(session).fullText();
        assertTrue(full.contains("New title"));assertFalse(full.contains("Old title"));
    }

}
