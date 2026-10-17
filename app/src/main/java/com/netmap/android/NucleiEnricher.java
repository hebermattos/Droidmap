package com.netmap.android;

import android.content.Context;
import org.json.JSONObject;
import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

/** Optional Nuclei runner. Requires a genuine Android ARM64 executable packaged as libnuclei.so. */
final class NucleiEnricher {
    private NucleiEnricher() {}

    static List<String> enrich(Context context, DeviceEvidence evidence, BooleanSupplier cancelled) {
        List<String> notices=new ArrayList<>();
        File binary=new File(context.getApplicationInfo().nativeLibraryDir,"libnuclei.so");
        if(!binary.isFile()) {
            notices.add("Nuclei unavailable: an Android-compatible ARM64 executable is not bundled.");
            return notices;
        }
        File template=new File(context.getFilesDir(),"nuclei-templates/droidmap-git-head.yaml");
        try {
            File parent=template.getParentFile();
            if(!parent.isDirectory()&&!parent.mkdirs())throw new IOException("Cannot create template directory");
            try(InputStream in=context.getAssets().open("nuclei/droidmap-git-head.yaml");
                OutputStream out=new FileOutputStream(template,false)) {
                byte[] bytes=new byte[4096];int n;
                while((n=in.read(bytes))!=-1)out.write(bytes,0,n);
            }
        } catch(IOException e) {
            notices.add("Nuclei template unavailable: "+DeviceEvidence.clean(e.getMessage()));
            return notices;
        }
        int checked=0,found=0;
        for(Map.Entry<String,List<DeviceEvidence.Observation>> entry:evidence.snapshot().entrySet()) {
            if(cancelled.getAsBoolean())break;
            String host=entry.getKey();
            SortedMap<Integer,String> services=new TreeMap<>();
            Set<Integer> opened=new HashSet<>();
            for(DeviceEvidence.Observation observation:entry.getValue()) {
                if(observation.source.equals("Nmap")&&observation.field.equals("openPort")&&observation.value.endsWith("/tcp"))
                    try {opened.add(Integer.parseInt(observation.value.split("/")[0]));}catch(NumberFormatException ignored){}
                if(observation.source.startsWith("Nmap service ")&&observation.field.equals("serviceName"))
                    try {services.put(Integer.parseInt(observation.source.substring(13)),observation.value);}catch(NumberFormatException ignored){}
            }
            for(Map.Entry<Integer,String> service:services.entrySet()) {
                if(cancelled.getAsBoolean())break;
                int port=service.getKey();
                if(!opened.contains(port))continue;
                String name=service.getValue().toLowerCase(Locale.ROOT);
                boolean https=name.equals("https")||name.equals("ssl/http")||name.equals("https-alt");
                if(!https&&!name.equals("http")&&!name.equals("http-alt")&&!name.equals("http-proxy"))continue;
                String address=ScanPlan.isIpv6(host)?"["+ScanPlan.stripZone(host)+"]":host;
                String url=(https?"https":"http")+"://"+address+":"+port+"/";
                Process process=null;
                try {
                    process=new ProcessBuilder(binary.getAbsolutePath(),"-u",url,"-t",template.getAbsolutePath(),
                            "-jsonl","-silent","-rate-limit","5","-timeout","5")
                            .redirectErrorStream(true).start();
                    checked++;
                    // Consume output with a strict bound and an overall process deadline.
                    long end=System.currentTimeMillis()+30000L;
                    BufferedReader reader=new BufferedReader(new InputStreamReader(process.getInputStream()));
                    while(!cancelled.getAsBoolean()&&System.currentTimeMillis()<end) {
                        if(!reader.ready()) {
                            if(!process.isAlive())break;
                            Thread.sleep(50);continue;
                        }
                        String line=reader.readLine();
                        if(line==null)break;
                        if(line.length()>16384)continue;
                        try {
                            JSONObject result=new JSONObject(line);
                            JSONObject info=result.optJSONObject("info");
                            if(info==null||result.optString("template-id").isEmpty())continue;
                            String severity=info.optString("severity","unknown");
                            if(!Arrays.asList("medium","high","critical").contains(severity.toLowerCase(Locale.ROOT)))continue;
                            String title=info.optString("name",result.optString("template-id"));
                            String finding=title+" ["+severity+"]";
                            String description=info.optString("description",result.optString("matched-at",url));
                            evidence.add(host,"Nuclei","finding:"+port+":"+DeviceEvidence.clean(finding),
                                    "VULNERABLE — "+DeviceEvidence.clean(description));
                            found++;
                        } catch(org.json.JSONException ignored) { /* log lines are not findings */ }
                    }
                    if(cancelled.getAsBoolean()||process.isAlive())process.destroyForcibly();
                    else if(process.exitValue()!=0)notices.add("Nuclei failed for "+url+" (exit "+process.exitValue()+").");
                } catch(Exception error) {
                    notices.add("Nuclei "+host+": "+DeviceEvidence.clean(error.getMessage()==null?error.toString():error.getMessage()));
                } finally {if(process!=null)process.destroyForcibly();}
            }
        }
        notices.add("Nuclei: "+checked+" web endpoints checked; "+found+" template matches (verification required).");
        return notices;
    }
}
