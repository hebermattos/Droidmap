package com.netmap.android;

import android.content.Context;
import java.io.*;
import java.util.*;

/** Runs the packaged ARM64 Nmap as bounded, optional enrichment for responsive hosts. */
final class NmapEnricher {
    private NmapEnricher() {}

    static List<String> enrich(Context context,ScanPlan plan,List<TcpScanner.Result> checks,DeviceEvidence evidence,java.util.function.BooleanSupplier cancelled) {
        List<String> notices=new ArrayList<>();
        File binary=new File(context.getApplicationInfo().nativeLibraryDir,"libnmap.so");
        if(!binary.isFile()) { notices.add("Nmap enrichment unavailable for this device ABI."); return notices; }
        File data;
        try { data=installData(context); }
        catch(IOException e) { notices.add("Nmap data unavailable: "+e.getMessage()); return notices; }

        LinkedHashSet<String> responders=new LinkedHashSet<>();
        for(TcpScanner.Result check:checks)
            if(check.state==TcpScanner.State.OPEN || check.state==TcpScanner.State.CLOSED) responders.add(check.host);
        for(Map.Entry<String,List<DeviceEvidence.Observation>> device:evidence.snapshot().entrySet()) {
            boolean peer=device.getValue().stream().anyMatch(o->o.source.equals("mDNS")||o.source.equals("IPv6 neighbor"));
            boolean own=device.getValue().stream().anyMatch(o->o.field.equals("addressOrigin")&&o.value.equals("This phone"));
            if(peer&&!own) responders.add(device.getKey());
        }
        NmapRunner runner=new NmapRunner(null,cancelled); int attempted=0, enriched=0;
        for(String host:responders) {
            if(cancelled.getAsBoolean()||attempted>=plan.mode.fingerprintLimit) break;
            attempted++;
            try {
                LinkedHashSet<Integer> selected=new LinkedHashSet<>(plan.ports);
                for(DeviceEvidence.Endpoint endpoint:evidence.endpoints().getOrDefault(host,Collections.emptyList()))
                    if(selected.size()<256) selected.add(endpoint.port);
                String xml=runner.scan(binary.getAbsolutePath(),data.getAbsolutePath(),host,selected,plan.timeoutMs);
                NmapXmlParser.parse(xml,evidence); evidence.add(host,"Nmap","scanStatus","Completed"); enriched++;
                LinkedHashSet<Integer> openPorts=new LinkedHashSet<>();
                for(DeviceEvidence.Observation item:evidence.observations(host)) if(item.source.equals("Nmap")&&item.field.equals("openPort")) try { openPorts.add(Integer.parseInt(item.value.split("/",2)[0])); } catch(Exception ignored) {}
                if(!cancelled.getAsBoolean()&&!openPorts.isEmpty()) try {
                    String vulnXml=runner.vulnerabilityScan(binary.getAbsolutePath(),data.getAbsolutePath(),host,openPorts,plan.timeoutMs);
                    NmapXmlParser.parseVulnerabilities(vulnXml,evidence);
                    evidence.add(host,"Nmap vulnerabilities","scanStatus","Completed on "+openPorts.size()+" open port(s)");
                } catch(Exception vulnerabilityError) {
                    evidence.add(host,"Nmap vulnerabilities","scanStatus","Failed: "+DeviceEvidence.clean(vulnerabilityError.getMessage()==null?vulnerabilityError.getClass().getSimpleName():vulnerabilityError.getMessage()));
                }
            } catch(Exception e) {
                String error=DeviceEvidence.clean(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage());
                evidence.add(host,"Nmap","scanStatus","Failed: "+error);
                notices.add("Nmap "+host+": "+error);
            }
        }
        if(responders.size()>attempted) notices.add("Nmap host budget reached: "+(responders.size()-attempted)+" observed device(s) not attempted.");
        if(attempted>0) notices.add("Nmap service enrichment: "+enriched+" / "+attempted+" observed devices.");
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
