package com.netmap.android;

import org.json.*;
import java.util.*;

/** Tool panels are projections of individual attempts; the combined report stays intact. */
final class AnalysisPresentation {
    private AnalysisPresentation() {}
    static boolean toolPanel(JSONObject report) {
        String tool=report.optString("tool");
        return (tool.equals("nmap")||tool.equals("nuclei")||tool.equals("httpx")) && report.optJSONArray("analysisRuns")!=null;
    }
    static List<JSONObject> runs(JSONObject report) {
        List<JSONObject> result=new ArrayList<>();
        JSONArray runs=SessionAnalyses.runs(report);
        String tool=report.optString("tool");
        for(int i=0;i<runs.length();i++) {
            JSONObject run=runs.optJSONObject(i);
            if(run!=null && tool.equals(run.optString("tool")))result.add(run);
        }
        return result;
    }
    static ReportPresentation.Device device(JSONObject run) throws JSONException {
        String ip=run.getString("ip");int port=run.getInt("port");
        JSONArray evidence=SessionAnalyses.toolEvidence(run.getString("tool"),
                SessionAnalyses.observations(run.optJSONArray("evidence")));
        JSONObject scoped=new JSONObject().put("ip",ip).put("evidence",evidence);
        return new ReportPresentation.Device(scoped,Collections.singletonMap(ip,Collections.singleton(port)));
    }
    static String outcome(String status) {
        return switch(status) {
            case "completed" -> "Completed";
            case "failed" -> "Failed";
            case "cancelled" -> "Cancelled";
            default -> "Unknown";
        };
    }
}
