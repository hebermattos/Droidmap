package com.netmap.android;

import android.content.Context;
import java.io.*;
import java.util.*;

/** Runs the packaged ARM64 Nmap as bounded, optional enrichment for all found hosts with verified-open TCP ports. */
final class NmapEnricher {
    private NmapEnricher() {}

    static List<String> enrich(Context context,ScanPlan plan,List<TcpScanner.Result> checks,DeviceEvidence evidence,String customArgs,int versionIntensity,java.util.function.BooleanSupplier cancelled,java.util.function.Consumer<String> progress) {
        List<String> notices=new ArrayList<>();
        File binary=new File(context.getApplicationInfo().nativeLibraryDir,"libnmap.so");
        if(!binary.isFile()) { notices.add("Nmap enrichment unavailable for this device ABI."); for(String notice:notices)progress.accept(notice); return notices; }
        final NmapCommands templates;
        try(InputStream input=context.getAssets().open(NmapCommandsJson.ASSET)) {
            templates=NmapCommandsJson.parse(NmapRunner.readBounded(input,65536));
        } catch(Exception e) {
            notices.add("Nmap template unavailable or invalid: "+DeviceEvidence.clean(
                    e.getMessage()==null?e.getClass().getSimpleName():e.getMessage()));
            for(String notice:notices)progress.accept(notice); return notices;
        }
        File data;
        try { data=installData(context); }
        catch(IOException e) { notices.add("Nmap data unavailable: "+e.getMessage()); for(String notice:notices)progress.accept(notice); return notices; }

        final List<String> parsedCustomArgs;
        try { parsedCustomArgs=NmapCustomArgs.parse(customArgs); }
        catch(IllegalArgumentException e) { notices.add("Nmap custom parameters rejected: "+e.getMessage()); progress.accept(notices.get(0)); return notices; }
        Map<String,LinkedHashSet<Integer>> targets=NmapTargets.collect(checks,evidence);
        NmapOutputStore outputStore=new NmapOutputStore(context.getFilesDir()); int attempted=0, enriched=0;
        if(targets.isEmpty()) {notices.add("Nmap skipped: no verified-open TCP ports were found.");progress.accept(notices.get(0));}
        for(Map.Entry<String,LinkedHashSet<Integer>> target:targets.entrySet()) {
            String host=target.getKey();
            if(cancelled.getAsBoolean()) break;
            attempted++;
            NmapRunner runner=new NmapRunner(templates,null,cancelled,result->{
                String source=result.profile.equals("Service detection")?"Nmap":"Nmap vulnerabilities";
                try {evidence.nmapOutput(host,source,outputStore.save(result));}
                catch(IOException storageError) {
                    evidence.add(host,source,"outputStatus",storageError.getMessage());
                    notices.add("Nmap "+host+" output unavailable: "+storageError.getMessage());
                }
            },parsedCustomArgs,versionIntensity,progress);
            try {
                LinkedHashSet<Integer> selected=target.getValue();
                evidence.nmapStatus(host,"Nmap","Running service detection");progress.accept("Nmap • "+host+" • Starting service detection");
                String xml=runner.scan(binary.getAbsolutePath(),data.getAbsolutePath(),host,selected,plan.timeoutMs);
                try {NmapXmlParser.parse(xml,evidence);}
                catch(Exception parseError) {throw new IOException("Nmap process finished, but XML processing failed: "+parseError.getMessage(),parseError);} evidence.nmapStatus(host,"Nmap","Completed"); enriched++;
                LinkedHashSet<Integer> openPorts=new LinkedHashSet<>();
                for(DeviceEvidence.Observation item:evidence.observations(host)) {
                    if(!item.source.equals("Nmap")||!item.field.equals("openPort")||!item.value.endsWith("/tcp")) continue;
                    try {
                        int port=Integer.parseInt(item.value.split("/",2)[0]);
                        if(selected.contains(port)) openPorts.add(port);
                    } catch(NumberFormatException ignored) { }
                }
                if(!cancelled.getAsBoolean()&&!openPorts.isEmpty()) try {
                    StringJoiner targetPorts=new StringJoiner(",");
                    for(int port:openPorts) targetPorts.add(port+"/tcp");
                    evidence.add(host,"Nmap vulnerabilities","targetPorts",targetPorts.toString());
                    evidence.add(host,"Nmap vulnerabilities","selectionRule","NSE selects applicable scripts by port and detected service; host-level results are labeled separately.");
                    evidence.nmapStatus(host,"Nmap vulnerabilities","Running vulnerability detection");progress.accept("Nmap • "+host+" • Starting vulnerability detection");
                    String vulnXml=runner.vulnerabilityScan(binary.getAbsolutePath(),data.getAbsolutePath(),host,openPorts,plan.timeoutMs);
                    try {NmapXmlParser.parseVulnerabilities(vulnXml,evidence,openPorts);}
                    catch(Exception parseError) {throw new IOException("Nmap process finished, but vulnerability XML processing failed: "+parseError.getMessage(),parseError);}
                    evidence.nmapStatus(host,"Nmap vulnerabilities","Command finished on "+openPorts.size()+" target port(s); see script results. Missing findings do not prove absence of vulnerabilities.");
                } catch(Exception vulnerabilityError) {
                    evidence.nmapStatus(host,"Nmap vulnerabilities","Failed: "+DeviceEvidence.clean(vulnerabilityError.getMessage()==null?vulnerabilityError.getClass().getSimpleName():vulnerabilityError.getMessage()));
                }
            } catch(Exception e) {
                String error=DeviceEvidence.clean(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage());
                evidence.nmapStatus(host,"Nmap","Failed: "+error);
                notices.add("Nmap "+host+": "+error);
                progress.accept("Nmap • "+host+" • "+(cancelled.getAsBoolean()?"Cancelled: ":"Failed: ")+error);
            }
        }
        if(targets.size()>attempted) notices.add("Nmap cancelled: "+(targets.size()-attempted)+" target(s) not attempted.");
        if(attempted>0) notices.add("Nmap service enrichment: "+enriched+" / "+attempted+" attempted targets; "+targets.size()+" found targets with open TCP ports.");
        return notices;
    }

    private static File installData(Context context) throws IOException {
        return NmapDataFiles.install(context.getFilesDir(),name->context.getAssets().open("nmap-data/"+name));
    }
}
