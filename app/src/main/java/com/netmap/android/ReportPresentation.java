package com.netmap.android;

import org.json.*;
import java.util.*;

/** Shared report semantics for cards, filters and the readable full report. */
final class ReportPresentation {
    enum Status {
        COMPLETED("Completed"), RUNNING("Running"), FAILED("Failed"), CANCELLED("Cancelled"), NOT_RUN("Not executed"), UNKNOWN("Unknown");
        final String label;
        Status(String label){this.label=label;}
    }
    enum Filter {
        ALL("All"), OPEN("Open ports"), ALERTS("Alerts"), FAILURES("Failures");
        final String label;
        Filter(String label){this.label=label;}
    }
    static final class Finding {
        final String title, scope, evidence, assessment, action;
        final boolean alert;
        Finding(String title,String scope,String evidence) {
            this.title=title;this.scope=scope;this.evidence=evidence;
            String upper=evidence.toUpperCase(Locale.ROOT);
            boolean negative=upper.contains("NOT VULNERABLE")||upper.contains("NOT_VULNERABLE");
            boolean reported=!negative&&java.util.regex.Pattern.compile("(?:^|\\bSTATE:\\s*)VULNERABLE\\b").matcher(upper).find();
            boolean uncertain=upper.contains("ERROR")||upper.contains("TIMED OUT")||upper.contains("COULD NOT")||upper.contains("FAILED");
            alert=!negative&&(reported||upper.contains("VULNERABLE")||upper.startsWith("REVIEW:"));
            assessment=negative?"No vulnerability reported by this check":reported?"Reported vulnerable — confirmation required":alert?"Alert — review required":uncertain?"Inconclusive check":"Informational result";
            action=reported||alert?"Verify the evidence against the vendor advisory. If confirmed, update or restrict the affected service.":uncertain?"Check the diagnostic log and rerun this check.":"Review the evidence; this result is not a complete security assessment.";
        }
    }
    static final class Device {
        final JSONObject json;
        final String ip, name;
        final SortedSet<Integer> ports=new TreeSet<>();
        final Map<Integer,String> services=new HashMap<>(), versions=new HashMap<>();
        final List<JSONObject> evidence=new ArrayList<>();
        final List<Finding> findings=new ArrayList<>();
        final Status serviceStatus,vulnerabilityStatus;
        final String serviceMessage,vulnerabilityMessage,serviceOutput,vulnerabilityOutput;
        Device(JSONObject json,Map<String,Set<Integer>> open) {
            this.json=json;ip=json.optString("ip");
            String reported=json.optString("reportedName");
            name=reported.isEmpty()?json.optString("dnsHostname"):reported;
            ports.addAll(open.getOrDefault(ip,Collections.emptySet()));
            JSONArray items=json.optJSONArray("evidence");
            String service="",vulnerability="",serviceLog="",vulnerabilityLog="";
            boolean hasServiceEvidence=false,hasVulnerabilityEvidence=false;
            if(items!=null)for(int i=0;i<items.length();i++) {
                JSONObject item=items.optJSONObject(i);if(item==null)continue;evidence.add(item);
                String source=item.optString("source"),field=item.optString("field"),value=item.optString("value");
                if(source.equals("Nmap")) {
                    if(field.equals("scanStatus"))service=value;
                    if(field.equals("outputFile"))serviceLog=value;
                    if(field.equals("openPort")&&value.endsWith("/tcp")){addPort(ports,value.substring(0,value.length()-4));hasServiceEvidence=true;}
                }
                if(source.startsWith("Nmap service "))try {
                    hasServiceEvidence=true;
                    int port=Integer.parseInt(source.substring("Nmap service ".length()));
                    if(field.equals("serviceName"))services.put(port,value);
                    if(field.equals("banner"))versions.put(port,value);
                } catch(NumberFormatException ignored) { }
                if(source.equals("Nmap vulnerabilities")) {
                    if(field.equals("scanStatus"))vulnerability=value;
                    else if(field.equals("outputFile"))vulnerabilityLog=value;
                    else if(field.startsWith("port ")||field.startsWith("host-level")) {
                        int separator=field.indexOf(" • ");
                        if(separator>=0&&!field.endsWith(" • service")){findings.add(new Finding(field.substring(separator+3),field.substring(0,separator),value));hasVulnerabilityEvidence=true;}
                    }
                }
            }
            JSONArray analysis=json.optJSONArray("analysisFindings");
            if(analysis!=null)for(int i=0;i<analysis.length();i++) {
                String finding=analysis.optString(i);
                if(finding.startsWith("Review:"))findings.add(new Finding("Protocol warning","Device",finding));
            }
            serviceMessage=service;vulnerabilityMessage=vulnerability;
            serviceStatus=service.isEmpty()&&(!serviceLog.isEmpty()||hasServiceEvidence)?Status.UNKNOWN:status(service);
            vulnerabilityStatus=vulnerability.isEmpty()&&(!vulnerabilityLog.isEmpty()||hasVulnerabilityEvidence)?Status.UNKNOWN:status(vulnerability);
            serviceOutput=serviceLog;vulnerabilityOutput=vulnerabilityLog;
        }
        boolean hasAlerts(){for(Finding finding:findings)if(finding.alert)return true;return false;}
        boolean hasFailures(){return serviceStatus==Status.FAILED||vulnerabilityStatus==Status.FAILED;}
        boolean matches(Filter filter){return filter==Filter.ALL||filter==Filter.OPEN&&!ports.isEmpty()||filter==Filter.ALERTS&&hasAlerts()||filter==Filter.FAILURES&&hasFailures();}
        String vulnerabilitySummary() {
            if(vulnerabilityStatus!=Status.COMPLETED)return vulnerabilityStatus.label;
            if(findings.stream().anyMatch(f->f.alert))return "Alerts reported";
            return "No vulnerability alerts reported; coverage is limited";
        }
    }
    final JSONObject json;
    final List<Device> devices=new ArrayList<>();
    ReportPresentation(JSONObject json) {
        this.json=json;
        Map<String,Set<Integer>> open=new HashMap<>();
        for(String key:Arrays.asList("checks","advertisedEndpointChecks")) {
            JSONArray checks=json.optJSONArray(key);
            if(checks==null)continue;
            for(int i=0;i<checks.length();i++) {
                JSONObject check=checks.optJSONObject(i);
                if(check!=null&&check.optString("state").equals("OPEN")) {
                    int port=check.optInt("port");
                    if(port>=1&&port<=65535)open.computeIfAbsent(check.optString("ip"),ignored->new TreeSet<>()).add(port);
                }
            }
        }
        JSONArray inventory=json.optJSONArray("devices");
        if(inventory!=null)for(int i=0;i<inventory.length();i++) {
            JSONObject device=inventory.optJSONObject(i);if(device!=null)devices.add(new Device(device,open));
        }
    }
    static void addPort(Set<Integer> ports,String value){try {int port=Integer.parseInt(value);if(port>=1&&port<=65535)ports.add(port);}catch(NumberFormatException ignored){}}
    static Status status(String value) {
        String lower=value.toLowerCase(Locale.ROOT);
        if(lower.isEmpty())return Status.NOT_RUN;
        if(lower.contains("cancelled")||lower.contains("canceled"))return Status.CANCELLED;
        if(lower.startsWith("failed"))return Status.FAILED;
        if(lower.startsWith("running"))return Status.RUNNING;
        if(lower.startsWith("completed")||lower.startsWith("command finished"))return Status.COMPLETED;
        if(lower.startsWith("skipped")||lower.startsWith("not executed")||lower.startsWith("disabled"))return Status.NOT_RUN;
        return Status.UNKNOWN;
    }
    static String friendlyError(String message) {
        String lower=message.toLowerCase(Locale.ROOT);
        if(lower.contains("cancelled"))return "The analysis was cancelled.";
        if(lower.contains("nse_main.lua"))return "Nmap could not start: a required script file is missing.";
        if(lower.contains("permission denied")||lower.contains("error=13"))return "Android denied permission to start Nmap or access its files.";
        if(lower.contains("timed out"))return "Nmap exceeded the analysis time limit.";
        if(lower.contains("xml"))return "Nmap returned a response that the app could not read.";
        if(lower.contains("cannot run program")||lower.contains("cannot execute")||lower.contains("exec format"))return "Nmap could not start on this device.";
        return "Nmap could not complete this analysis. Open the technical log for the exact error.";
    }
    String scanStatus() {
        if(json.optBoolean("cancelled"))return "Cancelled — partial results";
        if(json.optBoolean("partial"))return "In progress — partial results";
        if(json.optBoolean("networkChanged")||json.optString("identificationStatus").equals("partial")||json.has("identificationComplete")&&!json.optBoolean("identificationComplete")||json.has("tcpScanComplete")&&!json.optBoolean("tcpScanComplete"))return "Completed with partial results";
        return "Completed";
    }
    String summary() {
        int ports=0,alerts=0,failures=0;
        for(Device device:devices) {
            ports+=device.ports.size();if(device.hasAlerts())alerts++;if(device.hasFailures())failures++;
        }
        return scanStatus()+"\nTarget: "+json.optString("target")+"\nDevices: "+devices.size()+"   Open TCP endpoints: "+ports
            +"\nDevices with alerts: "+alerts+"   Devices with Nmap failures: "+failures
            +"\nNmap services: "+profileCounts(false)+"\nNmap vulnerabilities: "+profileCounts(true)
            +(json.optBoolean("nmapEnabled",true)?"":"\nNmap was disabled for this scan.");
    }
    private String profileCounts(boolean vulnerabilities) {
        Map<Status,Integer> counts=new EnumMap<>(Status.class);
        for(Device device:devices)counts.merge(vulnerabilities?device.vulnerabilityStatus:device.serviceStatus,1,Integer::sum);
        StringJoiner text=new StringJoiner(" · ");
        for(Status status:Status.values())if(counts.containsKey(status))text.add(counts.get(status)+" "+status.label.toLowerCase(Locale.ROOT));
        return text.length()==0?"No executions recorded":text.toString();
    }
    String fullText() {
        StringBuilder text=new StringBuilder("SCAN SUMMARY\n").append(summary()).append("\n");
        if(json.has("plannedChecks"))text.append("Selected-port checks: ").append(json.optInt("completedChecks")).append(" / ").append(json.optInt("plannedChecks")).append("\n");
        for(Device device:devices) {
            text.append("\nDEVICE · ").append(device.ip).append(device.name.isEmpty()?"":" · "+device.name).append("\n")
                .append("Probable type: ").append(device.json.optString("probableType","Unknown")).append("\n")
                .append("Identity confidence: ").append(device.json.optString("identityConfidence","Unknown")).append("\n")
                .append("Nmap services: ").append(device.serviceStatus.label).append("\n")
                .append("Vulnerabilities: ").append(device.vulnerabilitySummary()).append("\n");
            for(String key:Arrays.asList("reportedManufacturer","reportedModel","dnsHostname"))if(!device.json.optString(key).isEmpty())text.append(label(key)).append(": ").append(device.json.optString(key)).append("\n");
            JSONArray macs=device.json.optJSONArray("macAddresses");
            if(macs!=null)for(int i=0;i<macs.length();i++){JSONObject mac=macs.optJSONObject(i);if(mac!=null)text.append("MAC: ").append(mac.optString("address")).append(" · ").append(mac.optString("source")).append(" · ").append(mac.optString("kind")).append("\n");}
            text.append("\nPorts and services\n");
            if(device.ports.isEmpty())text.append("No open TCP ports observed.\n");
            for(int port:device.ports)text.append(port).append("/TCP · ").append(device.services.getOrDefault(port,"Not identified")).append(" · ").append(device.versions.getOrDefault(port,"Version not identified")).append("\n");
            text.append("\nFindings\n");
            if(device.findings.isEmpty())text.append(device.vulnerabilityStatus==Status.COMPLETED?"No script findings reported; this does not prove absence of vulnerabilities.\n":"No vulnerability assessment completed for this device.\n");
            for(Finding finding:device.findings)text.append(finding.title).append(" · ").append(finding.scope).append("\n").append(finding.assessment).append("\nEvidence: ").append(finding.evidence).append("\nSuggested action: ").append(finding.action).append("\n\n");
            if(device.serviceStatus==Status.FAILED)text.append("Service analysis: ").append(friendlyError(device.serviceMessage)).append("\n");
            if(device.vulnerabilityStatus==Status.FAILED)text.append("Vulnerability analysis: ").append(friendlyError(device.vulnerabilityMessage)).append("\n");
            text.append("\nAdditional evidence\n");
            for(JSONObject item:device.evidence) {
                String source=item.optString("source"),field=item.optString("field");
                if(source.startsWith("Nmap")||field.equals("outputFile"))continue;
                text.append(source).append(" · ").append(label(field)).append(": ").append(item.optString("value")).append("\n");
            }
        }
        JSONArray notices=json.optJSONArray("identificationNotices");
        if(notices!=null&&notices.length()>0){text.append("\nSCAN NOTICES\n");for(int i=0;i<notices.length();i++)text.append(notices.optString(i)).append("\n");}
        if(json.has("historyComparison"))text.append("\nHISTORY COMPARISON\n").append(json.optString("historyComparison")).append("\n");
        return text.append("\nOpen ports do not establish vulnerabilities. Names and models are reported metadata; device types are inferred. Complete Nmap diagnostics are available in each device's technical log; JSON retains all evidence.\n").toString();
    }
    static String label(String field){String label=field.replaceAll("([a-z0-9])([A-Z])","$1 $2").replace('_',' ');return label.isEmpty()?"Observation":Character.toUpperCase(label.charAt(0))+label.substring(1);}
}
