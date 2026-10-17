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
        File templates=new File(context.getFilesDir(),"nuclei-templates");
        String[] templateNames={"droidmap-git-head.yaml","droidmap-env-exposure.yaml","droidmap-security-headers.yaml"};
        try {
            if(!templates.isDirectory()&&!templates.mkdirs())throw new IOException("Cannot create template directory");
            for(String name:templateNames) {
                try(InputStream in=context.getAssets().open("nuclei/"+name);
                    OutputStream out=new FileOutputStream(new File(templates,name),false)) {
                    byte[] bytes=new byte[4096];int n;
                    while((n=in.read(bytes))!=-1)out.write(bytes,0,n);
                }
            }
        } catch(IOException e) {
            notices.add("Nuclei templates unavailable: "+DeviceEvidence.clean(e.getMessage()));
            return notices;
        }
        // Nuclei writes configuration and cache files; Android's nativeLibraryDir is read-only.
        File runtimeHome=new File(context.getFilesDir(),"nuclei-home");
        File runtimeCache=new File(context.getCacheDir(),"nuclei-cache");
        if((!runtimeHome.isDirectory()&&!runtimeHome.mkdirs()) ||
           (!runtimeCache.isDirectory()&&!runtimeCache.mkdirs())) {
            notices.add("Nuclei unavailable: cannot initialize writable runtime directories.");
            return notices;
        }
        int checked=0,found=0,completed=0,failed=0;
        for(Map.Entry<String,List<DeviceEvidence.Observation>> entry:evidence.snapshot().entrySet()) {
            if(cancelled.getAsBoolean())break;
            String host=entry.getKey();
            SortedMap<Integer,String> services=new TreeMap<>();
            Set<Integer> opened=new HashSet<>();
            SortedMap<Integer,String> webEndpoints=new TreeMap<>();
            for(DeviceEvidence.Observation observation:entry.getValue()) {
                if(observation.source.equals("Nmap")&&observation.field.equals("openPort")&&observation.value.endsWith("/tcp"))
                    try {opened.add(Integer.parseInt(observation.value.split("/")[0]));}catch(NumberFormatException ignored){}
                if((observation.source.startsWith("HTTP tcp/")||observation.source.startsWith("HTTPS tcp/")) &&
                        (observation.field.equals("webUrl")||observation.field.equals("server")||observation.field.equals("httpTitle")))
                    try {
                        int slash=observation.source.indexOf('/');
                        int webPort=Integer.parseInt(observation.source.substring(slash+1));
                        if(webPort>0&&webPort<=65535)
                            webEndpoints.put(webPort,observation.source.startsWith("HTTPS")?"https":"http");
                    }catch(NumberFormatException ignored){}
                if(observation.source.startsWith("Nmap service ")&&observation.field.equals("serviceName"))
                    try {services.put(Integer.parseInt(observation.source.substring(13)),observation.value);}catch(NumberFormatException ignored){}
            }
            for(Map.Entry<Integer,String> service:services.entrySet()) {
                String name=service.getValue().toLowerCase(Locale.ROOT);
                if(!opened.contains(service.getKey()))continue;
                if(name.equals("https")||name.equals("ssl/http")||name.equals("https-alt"))
                    webEndpoints.putIfAbsent(service.getKey(),"https");
                else if(name.equals("http")||name.equals("http-alt")||name.equals("http-proxy"))
                    webEndpoints.putIfAbsent(service.getKey(),"http");
            }
            for(Map.Entry<Integer,String> service:webEndpoints.entrySet()) {
                if(cancelled.getAsBoolean())break;
                int port=service.getKey();
                boolean https=service.getValue().equals("https");
                String address=ScanPlan.isIpv6(host)?"["+ScanPlan.stripZone(host)+"]":host;
                String url=(https?"https":"http")+"://"+address+":"+port+"/";
                Process process=null;
                try {
                    ProcessBuilder command=new ProcessBuilder(binary.getAbsolutePath(),"-u",url,"-t",templates.getAbsolutePath(),
                            "-jsonl","-silent","-rate-limit","5","-timeout","5","-disable-update-check")
                            .directory(runtimeHome)
                            .redirectErrorStream(true);
                    command.environment().put("HOME",runtimeHome.getAbsolutePath());
                    command.environment().put("XDG_CONFIG_HOME",new File(runtimeHome,".config").getAbsolutePath());
                    command.environment().put("XDG_CACHE_HOME",runtimeCache.getAbsolutePath());
                    command.environment().put("TMPDIR",context.getCacheDir().getAbsolutePath());
                    process=command.start();
                    checked++;
                    String endpointStatus="incomplete";
                    StringBuilder errors=new StringBuilder();
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
                            if(severity.isEmpty())severity="unknown";
                            String title=info.optString("name",result.optString("template-id"));
                            String finding=title+" ["+severity+"]";
                            String description=info.optString("description",result.optString("matched-at",url));
                            evidence.add(host,"Nuclei","finding:"+port+":"+DeviceEvidence.clean(finding),
                                    "VULNERABLE — "+DeviceEvidence.clean(description));
                            found++;
                        } catch(org.json.JSONException ignored) {
                            if(errors.length()<1200)errors.append(line,0,Math.min(line.length(),300)).append(" | ");
                        }
                    }
                    if(cancelled.getAsBoolean()||process.isAlive()) {
                        failed++;process.destroyForcibly();
                        notices.add("Nuclei incomplete for "+url+" (cancelled or exceeded 30s).");
                    } else if(process.exitValue()!=0) {
                        failed++;
                        String detail=errors.length()==0?"no diagnostic output":DeviceEvidence.clean(errors.toString());
                        notices.add("Nuclei failed for "+url+" (exit "+process.exitValue()+"): "+detail);
                    } else {completed++;endpointStatus="completed";}
                    evidence.add(host,"Nuclei","endpoint:"+port,service.getValue()+" • "+endpointStatus+" • "+templateNames.length+" configured templates");
                } catch(Exception error) {
                    failed++;
                    evidence.add(host,"Nuclei","endpoint:"+port,service.getValue()+" • failed");
                    notices.add("Nuclei "+host+": "+DeviceEvidence.clean(error.getMessage()==null?error.toString():error.getMessage()));
                } finally {if(process!=null)process.destroyForcibly();}
            }
        }
        notices.add("Nuclei: "+checked+" web endpoints attempted; "+completed+" completed; "+failed+" failed/incomplete; "+found+" findings; "+templateNames.length+" bundled templates (verification required).");
        if(checked==0)notices.add("Nuclei skipped: no HTTP/HTTPS endpoints confirmed by HTTP probes or Nmap.");
        return notices;
    }
}
