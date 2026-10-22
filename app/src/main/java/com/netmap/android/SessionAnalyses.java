package com.netmap.android;

import org.json.*;
import java.util.*;

/** Latest attempt per tool/IP/port, tied to one completed Discovery, never an authorization source. */
final class SessionAnalyses {
    static final int MAX_ENDPOINTS = 128;
    private SessionAnalyses() {}

    static boolean sameDiscovery(JSONObject baseline, JSONObject session) {
        return session != null && baseline.optLong("startedAtEpochMs", -1) >= 0
                && baseline.optLong("startedAtEpochMs", -1) == session.optLong("startedAtEpochMs", -2)
                && baseline.optString("target").equals(session.optString("target"))
                && !baseline.optString("networkScope").isEmpty()
                && baseline.optString("networkScope").equals(session.optString("networkScope"));
    }
    static boolean matches(JSONObject run, String tool, String ip, int port) {
        return run != null && tool.equals(run.optString("tool")) && ip.equals(run.optString("ip")) && port == run.optInt("port");
    }
    static JSONArray runs(JSONObject session) {
        JSONArray runs = session == null ? null : session.optJSONArray("analysisRuns");
        return runs == null ? new JSONArray() : runs;
    }
    static void checkCapacity(JSONObject session, String tool, String ip, int port) {
        JSONArray runs = runs(session);
        for (int i=0;i<runs.length();i++) if (matches(runs.optJSONObject(i),tool,ip,port)) return;
        if (runs.length() >= MAX_ENDPOINTS)
            throw new IllegalStateException("Session limit reached (128 tool/IP/port results). Export results and run Discovery again.");
    }
    static String endpointStatus(JSONObject report, String tool, String ip, int port) {
        JSONArray runs = runs(report);
        for (int i=0;i<runs.length();i++) {
            JSONObject run = runs.optJSONObject(i);
            if (run != null && matches(run,tool,ip,port)) return run.optString("status", "unknown");
        }
        return "";
    }
    static String status(String tool, List<DeviceEvidence.Observation> observations, boolean cancelled) {
        if (cancelled) return "cancelled";
        boolean complete = false, failed = false;
        for (DeviceEvidence.Observation item:observations) {
            if(tool.equals("httpx") && item.source.startsWith("HTTPX tcp/") && item.field.equals("scanStatus")) {
                complete |= item.value.equals("completed");
                failed |= !item.value.equals("completed");
            } else if (tool.equals("nuclei") && item.source.equals("Nuclei") && item.field.startsWith("endpoint:")) {
                String[] parts=item.value.split(" • ");
                String status=parts.length>1?parts[1]:"";
                complete |= status.equals("completed");
                failed |= !status.equals("completed");
            } else if (tool.equals("nmap") && item.source.startsWith("Nmap") && item.field.equals("scanStatus")) {
                ReportPresentation.Status status=ReportPresentation.status(item.value);
                complete |= status==ReportPresentation.Status.COMPLETED;
                failed |= status!=ReportPresentation.Status.COMPLETED;
            }
        }
        return failed || !complete ? "failed" : "completed";
    }
    static JSONObject append(JSONObject baseline, JSONObject session, JSONObject run) throws Exception {
        if (!sameDiscovery(baseline,session)) session=null;
        String tool=run.getString("tool"),ip=run.getString("ip"); int port=run.getInt("port");
        checkCapacity(session,tool,ip,port);
        JSONArray updated=new JSONArray(),previous=runs(session);
        for (int i=0;i<previous.length();i++) {
            JSONObject old=previous.getJSONObject(i);
            if (!matches(old,tool,ip,port)) updated.put(new JSONObject(old.toString()));
        }
        updated.put(new JSONObject(run.toString()));
        JSONObject result=new JSONObject(baseline.toString());
        result.put("analysisRuns",updated);
        result.put("analysisLimit",MAX_ENDPOINTS);
        Map<String,List<DeviceEvidence.Observation>> all=new LinkedHashMap<>();
        JSONArray devices=baseline.optJSONArray("devices");
        if (devices!=null) for (int i=0;i<devices.length();i++) {
            JSONObject device=devices.getJSONObject(i);
            all.put(device.getString("ip"),observations(device.optJSONArray("evidence")));
        }
        LinkedHashSet<String> notices=new LinkedHashSet<>();
        addNotices(notices,baseline.optJSONArray("identificationNotices"));
        Map<String,Map<String,String>> diagnostics=new HashMap<>();
        for (int i=0;i<updated.length();i++) {
            JSONObject attempt=updated.getJSONObject(i);
            List<DeviceEvidence.Observation> merged=all.computeIfAbsent(attempt.getString("ip"),key->new ArrayList<>());
            for (DeviceEvidence.Observation item:observations(attempt.optJSONArray("evidence"))) {
                if (item.field.equals("scanStatus") && item.source.startsWith("Nmap")) {
                    Map<String,String> bySource=diagnostics.computeIfAbsent(attempt.getString("ip"),key->new LinkedHashMap<>());
                    String old=bySource.get(item.source);
                    if (old==null || rank(item.value)>rank(old)) bySource.put(item.source,item.value);
                } else if (!item.field.equals("outputFile")) {
                    boolean duplicate=false;
                    for (DeviceEvidence.Observation old:merged)
                        if(old.source.equals(item.source)&&old.field.equals(item.field)&&old.value.equals(item.value)) {duplicate=true;break;}
                    if(!duplicate) merged.add(item);
                }
            }
            addNotices(notices,attempt.optJSONArray("notices"));
        }
        JSONArray mergedDevices=new JSONArray();
        for (Map.Entry<String,List<DeviceEvidence.Observation>> entry:all.entrySet()) {
            Map<String,String> statuses=diagnostics.getOrDefault(entry.getKey(),Collections.emptyMap());
            for(Map.Entry<String,String> status:statuses.entrySet())
                entry.getValue().add(new DeviceEvidence.Observation(status.getKey(),"scanStatus",status.getValue()));
            mergedDevices.put(ScanReport.device(entry.getKey(),entry.getValue()));
        }
        result.put("devices",mergedDevices).put("identificationNotices",new JSONArray(notices));
        result.put("tool",tool).put("toolLog",run.optString("log"));
        result.put("selectedIp",ip).put("selectedPort",port);
        result.put("finishedAtEpochMs",run.getLong("finishedAtEpochMs"));
        // Cancellation belongs to the endpoint attempt, never to the Discovery baseline.
        result.put("lastAnalysisCancelled",run.optString("status").equals("cancelled"));
        result.put("httpxEnabled",hasTool(updated,"httpx"));
        result.put("nmapEnabled",hasTool(updated,"nmap")).put("nucleiEnabled",hasTool(updated,"nuclei"));
        return result;
    }
    private static boolean hasTool(JSONArray runs,String tool) {
        for(int i=0;i<runs.length();i++)if(tool.equals(runs.optJSONObject(i).optString("tool")))return true;
        return false;
    }
    private static int rank(String status) {
        ReportPresentation.Status value=ReportPresentation.status(status);
        return value==ReportPresentation.Status.FAILED?4:value==ReportPresentation.Status.CANCELLED?3
                :value==ReportPresentation.Status.COMPLETED?0:2;
    }
    private static void addNotices(Set<String> result,JSONArray values) {
        if(values!=null)for(int i=0;i<values.length();i++)result.add(values.optString(i));
    }
    static List<DeviceEvidence.Observation> observations(JSONArray values) {
        List<DeviceEvidence.Observation> result=new ArrayList<>();
        if(values!=null)for(int i=0;i<values.length();i++) {
            JSONObject value=values.optJSONObject(i);
            if(value!=null) result.add(new DeviceEvidence.Observation(value.optString("source"),value.optString("field"),value.optString("value")));
        }
        return result;
    }
    static JSONArray toolEvidence(String tool,List<DeviceEvidence.Observation> observations) throws JSONException {
        JSONArray result=new JSONArray();
        for(DeviceEvidence.Observation item:observations)
            if(tool.equals("nmap")?item.source.startsWith("Nmap")
                    :tool.equals("httpx")?item.source.startsWith("HTTPX tcp/"):item.source.equals("Nuclei"))
                result.put(new JSONObject().put("source",item.source).put("field",item.field).put("value",item.value));
        return result;
    }
}
