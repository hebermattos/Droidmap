package com.netmap.android;

import org.json.*;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class SessionAnalysesTest {
    private JSONObject baseline() throws Exception {
        return new JSONObject().put("target","192.168.0.0/24").put("networkScope","wifi-one")
                .put("startedAtEpochMs",1000L).put("tool","discovery").put("cancelled",false)
                .put("discoveryReady",true).put("tcpScanComplete",true)
                .put("checks",new JSONArray().put(new JSONObject().put("ip","192.168.0.1").put("port",80).put("state","OPEN")))
                .put("devices",new JSONArray().put(ScanReport.device("192.168.0.1",List.of(
                        new DeviceEvidence.Observation("HTTP tcp/80","httpTitle","Router")))));
    }
    private JSONObject run(String tool,String ip,int port,String status,String value) throws Exception {
        return new JSONObject().put("tool",tool).put("ip",ip).put("port",port).put("status",status)
                .put("startedAtEpochMs",2000L).put("finishedAtEpochMs",3000L)
                .put("evidence",new JSONArray().put(new JSONObject().put("source",tool.equals("nmap")?"Nmap service "+port:"Nuclei")
                        .put("field",tool.equals("nmap")?"banner":"finding:"+port+":fixture").put("value",value)))
                .put("notices",new JSONArray().put("Fixture notice"));
    }
    @Test public void accumulatesAcrossHostsPortsAndToolsAndReplacesOnlyRepeatedKey() throws Exception {
        JSONObject baseline=baseline();
        JSONObject session=SessionAnalyses.append(baseline,null,run("nmap","192.168.0.1",80,"completed","old"));
        session=SessionAnalyses.append(baseline,session,run("nmap","192.168.0.1",443,"completed","TLS"));
        session=SessionAnalyses.append(baseline,session,run("nuclei","192.168.0.1",80,"completed","INFO"));
        session=SessionAnalyses.append(baseline,session,run("nmap","192.168.0.2",80,"completed","Other host"));
        session=SessionAnalyses.append(baseline,session,run("nmap","192.168.0.1",80,"failed","replacement"));
        assertEquals(4,SessionAnalyses.runs(session).length());
        String serialized=session.toString();
        assertFalse(serialized.contains("\"old\""));assertTrue(serialized.contains("replacement"));
        assertTrue(serialized.contains("TLS"));assertTrue(serialized.contains("Other host"));
        assertEquals("failed",SessionAnalyses.endpointStatus(session,"nmap","192.168.0.1",80));
        assertEquals("completed",SessionAnalyses.endpointStatus(session,"nuclei","192.168.0.1",80));
        assertEquals(1,baseline.getJSONArray("devices").length());
        assertFalse(baseline.has("analysisRuns"));
        assertTrue(serialized.contains("Router"));
        assertTrue(new ReportPresentation(session).fullText().contains("SESSION ANALYSES"));
    }
    @Test public void doesNotReuseResultsAcrossDiscoveriesOrNetworks() throws Exception {
        JSONObject baseline=baseline();
        JSONObject session=SessionAnalyses.append(baseline,null,run("nmap","192.168.0.1",80,"completed","old"));
        JSONObject fresh=new JSONObject(baseline.toString()).put("startedAtEpochMs",4000L);
        assertFalse(SessionAnalyses.sameDiscovery(fresh,session));
        assertFalse(SessionAnalyses.sameDiscovery(new JSONObject(baseline.toString()).put("networkScope","wifi-two"),session));
        JSONObject result=SessionAnalyses.append(fresh,session,run("nuclei","192.168.0.1",443,"completed","new"));
        assertEquals(1,SessionAnalyses.runs(result).length());assertFalse(result.toString().contains("\"old\""));
    }
    @Test public void cancellationIsPerEndpointAndExportRetainsCoverageAndBaseline() throws Exception {
        JSONObject attempt=run("nuclei","192.168.0.1",80,"cancelled","partial");
        attempt.put("coverage",new JSONObject().put("groups",new JSONArray(NucleiTemplates.groups(1)))
                .put("templates",new JSONArray(NucleiTemplates.files(1))).put("configuredTemplateCount",3)
                .put("successfulTemplateCount",JSONObject.NULL));
        JSONObject result=SessionAnalyses.append(baseline(),null,attempt);
        result=new JSONObject(result.toString());
        assertFalse(result.getBoolean("cancelled"));assertTrue(result.getBoolean("discoveryReady"));
        assertTrue(result.getBoolean("lastAnalysisCancelled"));
        assertEquals("cancelled",SessionAnalyses.endpointStatus(result,"nuclei","192.168.0.1",80));
        assertTrue(SessionAnalyses.runs(result).getJSONObject(0).getJSONObject("coverage").isNull("successfulTemplateCount"));
        assertTrue(new ReportPresentation(result).fullText().contains("3 configured templates"));
    }
    @Test public void capacityRejectsNewKeysButPermitsRerunsWithoutEviction() throws Exception {
        JSONArray runs=new JSONArray();
        for(int i=1;i<=SessionAnalyses.MAX_ENDPOINTS;i++)runs.put(run("nmap","192.168.0.1",i,"completed","fixture"));
        JSONObject session=new JSONObject().put("analysisRuns",runs);
        SessionAnalyses.checkCapacity(session,"nmap","192.168.0.1",1);
        try {SessionAnalyses.checkCapacity(session,"nmap","192.168.0.1",1000);fail("must reject overflow");}
        catch(IllegalStateException expected) {assertTrue(expected.getMessage().contains("128"));}
        assertEquals(128,runs.length());
    }
    @Test public void aggregationRetainsEndpointEvidenceBeyondPerProbeLimitAndWorstStatus() throws Exception {
        JSONObject baseline=baseline(),session=null;
        for(int port=1;port<=6;port++) {
            JSONObject run=run("nmap","192.168.0.1",port,"completed","banner"+port);
            JSONArray evidence=run.getJSONArray("evidence");
            for(int i=0;i<10;i++)evidence.put(new JSONObject().put("source","Nmap service "+port).put("field","fixture"+i).put("value","value"));
            evidence.put(new JSONObject().put("source","Nmap").put("field","scanStatus").put("value",port==1?"Failed: fixture":"Completed"));
            session=SessionAnalyses.append(baseline,session,run);
        }
        assertTrue(session.getJSONArray("devices").getJSONObject(0).getJSONArray("evidence").length()>48);
        assertEquals(ReportPresentation.Status.FAILED,new ReportPresentation(session).devices.get(0).serviceStatus);
    }
    @Test public void missingExecutionAndPartialFailuresAreNotCompleted() {
        assertEquals("failed",SessionAnalyses.status("nmap",List.of(),false));
        assertEquals("cancelled",SessionAnalyses.status("nuclei",List.of(),true));
        assertEquals("completed",SessionAnalyses.status("nmap",List.of(new DeviceEvidence.Observation("Nmap","scanStatus","Completed")),false));
        assertEquals("failed",SessionAnalyses.status("nmap",List.of(new DeviceEvidence.Observation("Nmap","scanStatus","Completed"),new DeviceEvidence.Observation("Nmap vulnerabilities","scanStatus","Failed: fixture")),false));
    }
}
