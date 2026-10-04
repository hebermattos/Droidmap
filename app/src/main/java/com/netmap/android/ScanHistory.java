package com.netmap.android;

import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** App-private compact history. Compare only complete scans of identical targets/ports. */
final class ScanHistory {
    private final File file;
    ScanHistory(File file) {this.file=file;}
    synchronized JSONArray load() throws IOException,JSONException {
        if(!file.exists()) return new JSONArray();
        if(file.length()>4*1024*1024) throw new IOException("History too large");
        return new JSONArray(new String(Files.readAllBytes(file.toPath()),StandardCharsets.UTF_8));
    }
    synchronized String save(JSONObject report,ScanPlan plan) throws IOException,JSONException {
        if(report.optBoolean("cancelled") || report.has("completedChecks") && report.optInt("completedChecks")!=plan.hosts.size()*plan.ports.size()) return "History comparison skipped for a cancelled scan.";
        if(report.optString("networkScope").isEmpty()) return "History comparison skipped: network identity unavailable.";
        if(report.optBoolean("networkChanged") || report.has("identificationComplete") && !report.optBoolean("identificationComplete")) return "History comparison skipped: identification partial or network changed.";
        JSONArray history=load(); JSONObject entry=compact(report,plan); JSONObject previous=null;
        for(int i=0;i<history.length();i++) if(history.getJSONObject(i).optString("targetKey").equals(entry.getString("targetKey"))) {previous=history.getJSONObject(i);break;}
        String changes=previous==null?"First completed scan for this target and port selection.":compare(previous,entry);
        entry.put("changes",changes); JSONArray updated=new JSONArray();updated.put(entry);
        for(int i=0;i<history.length() && updated.length()<20;i++) updated.put(history.getJSONObject(i));
        byte[] bytes=updated.toString().getBytes(StandardCharsets.UTF_8);
        while(bytes.length>4*1024*1024 && updated.length()>1) {updated.remove(updated.length()-1);bytes=updated.toString().getBytes(StandardCharsets.UTF_8);}
        if(bytes.length>4*1024*1024) throw new IOException("Scan summary too large");
        File temporary=new File(file.getParentFile(),file.getName()+".tmp");Files.write(temporary.toPath(),bytes);
        try {Files.move(temporary.toPath(),file.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
        catch(AtomicMoveNotSupportedException e) {Files.move(temporary.toPath(),file.toPath(),StandardCopyOption.REPLACE_EXISTING);}
        return changes;
    }
    static JSONObject compact(JSONObject report,ScanPlan plan) throws JSONException {
        JSONObject entry=new JSONObject();entry.put("target",report.getString("target"));entry.put("time",report.getLong("finishedAtEpochMs"));entry.put("mode",plan.mode.name());
        entry.put("networkScope",report.optString("networkScope"));entry.put("timeoutMs",plan.timeoutMs);entry.put("adaptive",plan.adaptive);
        entry.put("targetKey",report.optString("networkScope")+"/"+plan.mode+"/"+plan.timeoutMs+"/"+plan.adaptive+"/"+plan.hosts.get(0)+"/"+plan.hosts.get(plan.hosts.size()-1)+"/"+plan.ports);entry.put("ports",new JSONArray(plan.ports));
        Map<String,Set<Integer>> hosts=new TreeMap<>((a,b)->Long.compare(ScanPlan.ipv4(a),ScanPlan.ipv4(b)));
        for(String section:new String[]{"checks","advertisedEndpointChecks"}) {
            JSONArray checks=report.optJSONArray(section); if(checks==null) continue;
            for(int i=0;i<checks.length();i++) {JSONObject check=checks.getJSONObject(i);String state=check.optString("state");
                if(state.equals("OPEN") || state.equals("CLOSED")) {Set<Integer> ports=hosts.computeIfAbsent(check.getString("ip"),k->new TreeSet<>()); if(state.equals("OPEN")) ports.add(check.getInt("port"));}
            }
        }
        JSONArray devices=report.optJSONArray("devices");Map<String,JSONObject> info=new HashMap<>();
        if(devices!=null) for(int i=0;i<devices.length();i++) {JSONObject device=devices.getJSONObject(i);String ip=device.getString("ip");hosts.computeIfAbsent(ip,k->new TreeSet<>());info.put(ip,device);}
        JSONArray summary=new JSONArray();
        for(Map.Entry<String,Set<Integer>> host:hosts.entrySet()) {
            JSONObject device=new JSONObject();device.put("ip",host.getKey());device.put("openPorts",new JSONArray(host.getValue()));
            JSONObject source=info.get(host.getKey());if(source!=null) for(String key:new String[]{"reportedName","reportedModel","suggestedManufacturer","probableType","identityConfidence"}) device.put(key,source.optString(key));
            summary.put(device);
        }
        entry.put("devices",summary);return entry;
    }
    static Map<String,Set<Integer>> inventory(JSONObject entry) throws JSONException {
        Map<String,Set<Integer>> hosts=new TreeMap<>((a,b)->Long.compare(ScanPlan.ipv4(a),ScanPlan.ipv4(b)));JSONArray devices=entry.getJSONArray("devices");
        for(int i=0;i<devices.length();i++) {JSONObject device=devices.getJSONObject(i);Set<Integer> ports=new TreeSet<>();JSONArray values=device.getJSONArray("openPorts");for(int j=0;j<values.length();j++) ports.add(values.getInt(j));hosts.put(device.getString("ip"),ports);}return hosts;
    }
    static String compare(JSONObject previous,JSONObject current) throws JSONException {
        Map<String,Set<Integer>> before=inventory(previous),after=inventory(current);StringBuilder text=new StringBuilder();
        for(String ip:after.keySet()) {
            if(!before.containsKey(ip)) text.append("New responder: ").append(ip).append('\n');
            else {Set<Integer> added=new TreeSet<>(after.get(ip));added.removeAll(before.get(ip));Set<Integer> removed=new TreeSet<>(before.get(ip));removed.removeAll(after.get(ip));
                if(!added.isEmpty()) text.append(ip).append(" newly observed open ports: ").append(added).append('\n');
                if(!removed.isEmpty()) text.append(ip).append(" ports no longer observed open: ").append(removed).append('\n');}
        }
        for(String ip:before.keySet()) if(!after.containsKey(ip)) text.append("Not observed this scan: ").append(ip).append('\n');
        return text.length()==0?"No responder or open-port changes observed.":text.toString().trim();
    }
    static String describe(JSONObject entry) throws JSONException {
        StringBuilder text=new StringBuilder();text.append(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss",Locale.US).format(new Date(entry.getLong("time")))).append("\nTarget: ").append(entry.getString("target")).append("\n").append(entry.optString("changes")).append("\n\n");
        JSONArray devices=entry.getJSONArray("devices");for(int i=0;i<devices.length();i++) {JSONObject d=devices.getJSONObject(i);text.append(d.getString("ip")).append(" ").append(d.optString("reportedName")).append("\nOpen ports: ").append(d.getJSONArray("openPorts")).append("\n").append(d.optString("probableType")).append(" • ").append(d.optString("reportedModel")).append("\n\n");}return text.toString();
    }
}
