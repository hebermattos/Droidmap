package com.netmap.android;

import org.json.*;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class AnalysisPresentationTest {
    private JSONObject observation(String source,String field,String value) throws Exception {
        return new JSONObject().put("source",source).put("field",field).put("value",value);
    }
    private JSONObject run(String tool,String ip,int port,JSONArray evidence) throws Exception {
        return new JSONObject().put("tool",tool).put("ip",ip).put("port",port).put("status","completed").put("evidence",evidence);
    }
    @Test public void toolPanelsShowOnlyTheirAttemptsWithoutChangingExport() throws Exception {
        JSONObject nmap80=run("nmap","192.168.0.1",80,new JSONArray().put(observation("Nmap service 80","serviceName","http")));
        JSONObject nmap443=run("nmap","192.168.0.2",443,new JSONArray().put(observation("Nmap service 443","serviceName","https")));
        JSONObject nuclei=run("nuclei","192.168.0.1",80,new JSONArray().put(observation("Nuclei","finding:80:Headers [info]","INFORMATIONAL — missing headers")));
        JSONObject report=new JSONObject().put("tool","nmap").put("analysisRuns",new JSONArray().put(nmap80).put(nuclei).put(nmap443));
        String original=report.toString();
        List<JSONObject> shown=AnalysisPresentation.runs(report);
        assertEquals(2,shown.size());
        assertEquals(80,shown.get(0).getInt("port"));assertEquals(443,shown.get(1).getInt("port"));
        assertEquals(original,report.toString());
        report.put("tool","nuclei");assertEquals(1,AnalysisPresentation.runs(report).size());
        assertEquals(3,report.getJSONArray("analysisRuns").length());
    }
    @Test public void endpointFindingsAndVersionsCannotLeakFromAnotherTool() throws Exception {
        JSONArray evidence=new JSONArray()
                .put(observation("Nmap service 443","serviceName","https"))
                .put(observation("Nmap service 443","banner","fixture server"))
                .put(observation("Nmap vulnerabilities","port 443 • tls-fixture","REVIEW: fixture"))
                .put(observation("Nuclei","finding:80:Unrelated exposure","REVIEW: unrelated"));
        ReportPresentation.Device nmap=AnalysisPresentation.device(run("nmap","192.168.0.1",443,evidence));
        assertEquals(Set.of(443),nmap.ports);
        assertEquals("https",nmap.services.get(443));assertEquals("fixture server",nmap.versions.get(443));
        assertEquals(1,nmap.findings.size());assertEquals("port 443",nmap.findings.get(0).scope);
        assertFalse(nmap.findings.get(0).evidence.contains("unrelated"));
        ReportPresentation.Device nuclei=AnalysisPresentation.device(run("nuclei","192.168.0.1",80,evidence));
        assertEquals(1,nuclei.findings.size());assertEquals("Nuclei",nuclei.findings.get(0).source);
        assertTrue(nuclei.services.isEmpty());
    }
    @Test public void discoveryAndLegacyReportsKeepTheirExistingRenderPath() throws Exception {
        assertFalse(AnalysisPresentation.toolPanel(new JSONObject().put("tool","nmap")));
        assertFalse(AnalysisPresentation.toolPanel(new JSONObject().put("tool","discovery").put("analysisRuns",new JSONArray())));
        assertTrue(AnalysisPresentation.toolPanel(new JSONObject().put("tool","nuclei").put("analysisRuns",new JSONArray())));
    }
}
