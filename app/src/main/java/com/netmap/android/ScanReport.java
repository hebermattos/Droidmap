package com.netmap.android;

import org.json.*;
import java.util.*;

/** Complete scan report; independent of the activity lifecycle. */
final class ScanReport {
    static String describe(List<TcpScanner.Result> results, ScanPlan plan, boolean cancelled, Map<String,List<DeviceEvidence.Observation>> identified,List<String> notices,int initialCompleted,int extraCount) {
        Map<String, List<Integer>> hosts = new LinkedHashMap<>(); int errors = 0, silent = 0, open = 0;
        for (TcpScanner.Result result : results) {
            if (result.state == TcpScanner.State.OPEN || result.state == TcpScanner.State.CLOSED) hosts.computeIfAbsent(result.host, k -> new ArrayList<>());
            if (result.state == TcpScanner.State.OPEN) { hosts.get(result.host).add(result.port); open++; }
            if (result.state == TcpScanner.State.ERROR) errors++;
            if (result.state == TcpScanner.State.NO_RESPONSE) silent++;
        }
        for(String ip:identified.keySet()) hosts.computeIfAbsent(ip,k->new ArrayList<>());
        StringBuilder text = new StringBuilder();
        for (Map.Entry<String, List<Integer>> host : hosts.entrySet()) {
            text.append(host.getKey()).append("\n");
            List<DeviceEvidence.Observation> info=identified.getOrDefault(host.getKey(),Collections.emptyList());
            String name=DeviceEvidence.first(info,"friendlyName","serviceName","netbiosName","dnsHostname","httpTitle");
            String maker=DeviceEvidence.first(info,"manufacturer"), model=DeviceEvidence.first(info,"modelName","modelHint");
            text.append("  Name (reported): ").append(name.isEmpty()?"Unknown":name).append("\n");
            if(!maker.isEmpty()) text.append("  Manufacturer (reported): ").append(maker).append("\n");
            String mac=DeviceEvidence.first(info,"reportedMac");
            if(!mac.isEmpty()) text.append("  MAC (reported via NetBIOS): ").append(mac).append("\n");
            if(!model.isEmpty()) text.append("  Model (reported): ").append(model).append("\n");
            DeviceProfile profile=new DeviceProfile(info);
            if(!profile.manufacturer.isEmpty() && maker.isEmpty()) text.append("  Manufacturer (suggested): ").append(profile.manufacturer).append("\n");
            text.append("  Identification: ").append(profile.confidence).append("\n");
            for(String reason:profile.reasons) text.append("  Evidence: ").append(reason).append("\n");
            text.append("  Type (probable): ").append(DeviceEvidence.probableType(info)).append("\n");
            for(DeviceEvidence.Observation item:info) text.append("  [").append(item.source).append("] ").append(item.field).append(": ").append(item.value).append("\n");
            if (host.getValue().isEmpty()) text.append("  No selected TCP ports open.\n");
            for (int port : host.getValue()) text.append("  ").append(port).append("/tcp OPEN\n");
            text.append("\n");
        }
        if (hosts.isEmpty()) text.append("No responding devices detected.\n\n");
        for(String notice:notices) text.append("Notice: ").append(notice).append("\n");
        return text.append("Summary\nResponding devices: ").append(hosts.size()).append(" / ").append(plan.hosts.size())
            .append("\nOpen ports: ").append(open).append("\nNo response: ").append(silent).append("\nConnection errors: ").append(errors)
            .append("\nMode: ").append(plan.mode).append("\nAdvertised endpoint checks: ").append(extraCount).append("\nSelected-port checks: ").append(initialCompleted).append(" / ").append(plan.hosts.size() * plan.ports.size())
            .append(cancelled ? "\nPartial scan.\n" : "\n")
            .append("\nNo response can mean filtering, timeout or an offline device. Names and models are self-reported; probable types are inferred from advertised services. An open port does not establish a vulnerability.").toString();
    }
    static String json(List<TcpScanner.Result> results, ScanPlan plan, String target, boolean cancelled, long started, Map<String,List<DeviceEvidence.Observation>> identified,List<String> notices,List<TcpScanner.Result> endpointChecks) throws Exception {
        JSONObject report = new JSONObject(); report.put("schemaVersion", 4); report.put("adaptive",plan.adaptive); report.put("mode",plan.mode.name()); report.put("timeoutRetries",plan.mode.retries); report.put("target", target);
        report.put("startedAtEpochMs", started); report.put("finishedAtEpochMs", System.currentTimeMillis());
        report.put("cancelled", cancelled); report.put("timeoutMs", plan.timeoutMs); report.put("ports", new JSONArray(plan.ports));
        report.put("plannedChecks", plan.hosts.size() * plan.ports.size()); report.put("completedChecks", results.size());
        JSONArray checks = new JSONArray();
        for (TcpScanner.Result result : results) { JSONObject check = new JSONObject(); check.put("ip", result.host); check.put("port", result.port); check.put("protocol", "tcp"); check.put("state", result.state.name()); check.put("attempts",result.attempts); check.put("finalTimeoutMs",result.timeoutMs); checks.put(check); }
        JSONArray extraChecks=new JSONArray();
        for(TcpScanner.Result result:endpointChecks) { JSONObject entry=new JSONObject(); entry.put("ip",result.host); entry.put("port",result.port); entry.put("protocol","tcp"); entry.put("state",result.state.name()); entry.put("attempts",result.attempts); entry.put("finalTimeoutMs",result.timeoutMs); extraChecks.put(entry); }
        report.put("advertisedEndpointChecks",extraChecks);
        report.put("checks", checks); report.put("identificationNotices",new JSONArray(notices));
        JSONArray devices=new JSONArray();
        for(Map.Entry<String,List<DeviceEvidence.Observation>> host:identified.entrySet()) {
            JSONObject device=new JSONObject(); device.put("ip",host.getKey());
            device.put("dnsHostname",DeviceEvidence.first(host.getValue(),"dnsHostname"));
            device.put("reportedName",DeviceEvidence.first(host.getValue(),"friendlyName","serviceName","netbiosName","dnsHostname","httpTitle"));
            device.put("reportedMac",DeviceEvidence.first(host.getValue(),"reportedMac"));
            device.put("reportedManufacturer",DeviceEvidence.first(host.getValue(),"manufacturer"));
            device.put("reportedModel",DeviceEvidence.first(host.getValue(),"modelName","modelHint"));
            device.put("probableType",DeviceEvidence.probableType(host.getValue())); DeviceProfile profile=new DeviceProfile(host.getValue()); device.put("identityConfidence",profile.confidence);
            device.put("suggestedManufacturer",profile.manufacturer); device.put("identificationReasons",new JSONArray(profile.reasons));
            JSONArray observations=new JSONArray();
            for(DeviceEvidence.Observation item:host.getValue()) { JSONObject entry=new JSONObject(); entry.put("source",item.source); entry.put("field",item.field); entry.put("value",item.value); observations.put(entry); }
            device.put("evidence",observations); devices.put(device);
        }
        report.put("devices",devices); return report.toString(2);
    }
}
