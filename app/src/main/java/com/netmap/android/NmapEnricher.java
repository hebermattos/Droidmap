package com.netmap.android;

import android.content.Context;
import java.io.*;
import java.util.*;

/** Runs the packaged ARM64 Nmap as bounded, optional enrichment for all found hosts with verified-open TCP ports. */
final class NmapEnricher {
    private NmapEnricher() {}

    static List<String> enrich(Context context,ScanPlan plan,List<TcpScanner.Result> checks,DeviceEvidence evidence,java.util.function.BooleanSupplier cancelled) {
        List<String> notices=new ArrayList<>();
        File binary=new File(context.getApplicationInfo().nativeLibraryDir,"libnmap.so");
        if(!binary.isFile()) { notices.add("Nmap enrichment unavailable for this device ABI."); return notices; }
        final NmapCommands templates;
        try(InputStream input=context.getAssets().open(NmapCommandsJson.ASSET)) {
            templates=NmapCommandsJson.parse(NmapRunner.readBounded(input,65536));
        } catch(Exception e) {
            notices.add("Nmap template unavailable or invalid: "+DeviceEvidence.clean(
                    e.getMessage()==null?e.getClass().getSimpleName():e.getMessage()));
            return notices;
        }
        File data;
        try { data=installData(context); }
        catch(IOException e) { notices.add("Nmap data unavailable: "+e.getMessage()); return notices; }

        Map<String,LinkedHashSet<Integer>> targets=NmapTargets.collect(checks,evidence);
        NmapRunner runner=new NmapRunner(templates,null,cancelled); int attempted=0, enriched=0;
        for(Map.Entry<String,LinkedHashSet<Integer>> target:targets.entrySet()) {
            String host=target.getKey();
            if(cancelled.getAsBoolean()) break;
            attempted++;
            try {
                LinkedHashSet<Integer> selected=target.getValue();
                String xml=runner.scan(binary.getAbsolutePath(),data.getAbsolutePath(),host,selected,plan.timeoutMs);
                NmapXmlParser.parse(xml,evidence); evidence.add(host,"Nmap","scanStatus","Completed"); enriched++;
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
                    String vulnXml=runner.vulnerabilityScan(binary.getAbsolutePath(),data.getAbsolutePath(),host,openPorts,plan.timeoutMs);
                    NmapXmlParser.parseVulnerabilities(vulnXml,evidence,openPorts);
                    evidence.add(host,"Nmap vulnerabilities","scanStatus","Command finished on "+openPorts.size()+" target port(s); see script results. Missing findings do not prove absence of vulnerabilities.");
                } catch(Exception vulnerabilityError) {
                    evidence.add(host,"Nmap vulnerabilities","scanStatus","Failed: "+DeviceEvidence.clean(vulnerabilityError.getMessage()==null?vulnerabilityError.getClass().getSimpleName():vulnerabilityError.getMessage()));
                }
            } catch(Exception e) {
                String error=DeviceEvidence.clean(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage());
                evidence.add(host,"Nmap","scanStatus","Failed: "+error);
                notices.add("Nmap "+host+": "+error);
            }
        }
        if(targets.size()>attempted) notices.add("Nmap cancelled: "+(targets.size()-attempted)+" target(s) not attempted.");
        if(attempted>0) notices.add("Nmap service enrichment: "+enriched+" / "+attempted+" attempted targets; "+targets.size()+" found targets with open TCP ports.");
        return notices;
    }

    private static File installData(Context context) throws IOException {
        File dir=new File(context.getFilesDir(),"nmap-data");
        if(!dir.isDirectory() && !dir.mkdirs()) throw new IOException("cannot create data directory");
        List<String> names=new ArrayList<>(Arrays.asList("nmap-service-probes","nmap-services","nmap-protocols","nmap-rpc","scripts/script.db"));
        try(BufferedReader manifest=new BufferedReader(new InputStreamReader(context.getAssets().open("nmap-data/nse-files.txt")))) { String line; while((line=manifest.readLine())!=null) if(!line.trim().isEmpty()&&!names.contains(line)) names.add(line); }
        for(String name:names) {
            File target=new File(dir,name);
            if(target.isFile() && target.length()>0) continue;
            File parent=target.getParentFile(); if(parent!=null&&!parent.isDirectory()&&!parent.mkdirs()) throw new IOException("cannot create Nmap data subdirectory");
            try(InputStream in=context.getAssets().open("nmap-data/"+name); OutputStream out=new FileOutputStream(target)) {
                byte[] buffer=new byte[8192]; int read; while((read=in.read(buffer))!=-1) out.write(buffer,0,read);
            }
        }
        return dir;
    }
}
