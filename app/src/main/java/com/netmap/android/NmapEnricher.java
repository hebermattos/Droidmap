package com.netmap.android;

import android.content.Context;
import java.io.*;
import java.util.*;

/** Runs the packaged ARM64 Nmap as bounded, optional enrichment for responsive hosts. */
final class NmapEnricher {
    private NmapEnricher() {}

    static List<String> enrich(Context context,ScanPlan plan,List<TcpScanner.Result> checks,DeviceEvidence evidence) {
        List<String> notices=new ArrayList<>();
        if(plan.mode!=ScanPlan.Mode.COMPLETE) return notices;
        File binary=new File(context.getApplicationInfo().nativeLibraryDir,"libnmap.so");
        if(!binary.isFile()) { notices.add("Nmap enrichment unavailable for this device ABI."); return notices; }
        File data;
        try { data=installData(context); }
        catch(IOException e) { notices.add("Nmap data unavailable: "+e.getMessage()); return notices; }

        LinkedHashSet<String> responders=new LinkedHashSet<>();
        for(TcpScanner.Result check:checks)
            if(check.state==TcpScanner.State.OPEN || check.state==TcpScanner.State.CLOSED) responders.add(check.host);
        NmapRunner runner=new NmapRunner(); int attempted=0, enriched=0;
        for(String host:responders) {
            if(attempted>=plan.mode.fingerprintLimit) break;
            attempted++;
            try {
                String xml=runner.scan(binary.getAbsolutePath(),data.getAbsolutePath(),host,plan.ports,plan.timeoutMs);
                NmapXmlParser.parse(xml,evidence); enriched++;
            } catch(Exception e) {
                notices.add("Nmap "+host+": "+DeviceEvidence.clean(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage()));
            }
        }
        if(attempted>0) notices.add("Nmap service enrichment: "+enriched+" / "+attempted+" responsive devices.");
        return notices;
    }

    private static File installData(Context context) throws IOException {
        File dir=new File(context.getFilesDir(),"nmap-data");
        if(!dir.isDirectory() && !dir.mkdirs()) throw new IOException("cannot create data directory");
        for(String name:new String[]{"nmap-service-probes","nmap-services","nmap-protocols","nmap-rpc"}) {
            File target=new File(dir,name);
            if(target.isFile() && target.length()>0) continue;
            try(InputStream in=context.getAssets().open("nmap-data/"+name); OutputStream out=new FileOutputStream(target)) {
                byte[] buffer=new byte[8192]; int read; while((read=in.read(buffer))!=-1) out.write(buffer,0,read);
            }
        }
        return dir;
    }
}
