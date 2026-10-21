package com.netmap.android;

import android.content.Context;
import org.json.JSONObject;
import java.io.*;
import java.util.*;
import java.util.function.BooleanSupplier;

/** Optional Nuclei runner. Requires a genuine Android ARM64 executable packaged as libnuclei.so. */
final class NucleiEnricher {
    private NucleiEnricher() {}

    static List<String> enrich(Context context, DeviceEvidence evidence, Map<String, LinkedHashSet<Integer>> verifiedPorts, int coverageMask, BooleanSupplier cancelled,
            java.util.function.Consumer<String> progress) {
        List<String> notices=new ArrayList<>();
        ToolProgress log=new ToolProgress("Nuclei",progress);
        log.event("Preparing bundled templates and runtime");
        File binary=new File(context.getApplicationInfo().nativeLibraryDir,"libnuclei.so");
        if(!binary.isFile()) {
            notices.add("Nuclei unavailable: an Android-compatible ARM64 executable is not bundled.");
            log.event(notices.get(notices.size()-1));log.flush();
            return notices;
        }
        File templates=new File(context.getFilesDir(),"nuclei-templates");
        List<String> templateNames=NucleiTemplates.files(coverageMask);
        log.event("Coverage: "+NucleiTemplates.summary(coverageMask));
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
            log.event(notices.get(notices.size()-1));log.flush();
            return notices;
        }
        // Nuclei writes configuration and cache files; Android's nativeLibraryDir is read-only.
        File runtimeHome=new File(context.getFilesDir(),"nuclei-home");
        File runtimeCache=new File(context.getCacheDir(),"nuclei-cache");
        if((!runtimeHome.isDirectory()&&!runtimeHome.mkdirs()) ||
           (!runtimeCache.isDirectory()&&!runtimeCache.mkdirs())) {
            notices.add("Nuclei unavailable: cannot initialize writable runtime directories.");
            log.event(notices.get(notices.size()-1));log.flush();
            return notices;
        }
        StringJoiner templatePaths=new StringJoiner(",");
        for(String name:templateNames)templatePaths.add(new File(templates,name).getAbsolutePath());
        int checked=0,found=0,completed=0,failed=0;
        for(Map.Entry<String,List<DeviceEvidence.Observation>> entry:evidence.snapshot().entrySet()) {
            if(cancelled.getAsBoolean())break;
            String host=entry.getKey();
            Set<Integer> allowedPorts=verifiedPorts.getOrDefault(host,new LinkedHashSet<>());
            if(allowedPorts.isEmpty())continue;
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
                        if(allowedPorts.contains(webPort))
                            webEndpoints.put(webPort,observation.source.startsWith("HTTPS")?"https":"http");
                    }catch(NumberFormatException ignored){}
                if(observation.source.startsWith("Nmap service ")&&observation.field.equals("serviceName"))
                    try {services.put(Integer.parseInt(observation.source.substring(13)),observation.value);}catch(NumberFormatException ignored){}
            }
            for(Map.Entry<Integer,String> service:services.entrySet()) {
                String name=service.getValue().toLowerCase(Locale.ROOT);
                if(!opened.contains(service.getKey())||!allowedPorts.contains(service.getKey()))continue;
                if(name.equals("https")||name.equals("ssl/http")||name.equals("https-alt"))
                    webEndpoints.putIfAbsent(service.getKey(),"https");
                else if(name.equals("http")||name.equals("http-alt")||name.equals("http-proxy"))
                    webEndpoints.putIfAbsent(service.getKey(),"http");
            }
            for(Map.Entry<Integer,String> service:webEndpoints.entrySet()) {
                if(cancelled.getAsBoolean())break;
                int port=service.getKey();
                if(!allowedPorts.contains(port))continue;
                boolean https=service.getValue().equals("https");
                String address=ScanPlan.isIpv6(host)?"["+ScanPlan.stripZone(host)+"]":host;
                String url=(https?"https":"http")+"://"+address+":"+port+"/";
                Process process=null;
                try {
                    ProcessBuilder command=new ProcessBuilder(binary.getAbsolutePath(),"-u",url,"-t",templatePaths.toString(),
                            "-jsonl","-silent","-rate-limit","5","-disable-update-check")
                            .directory(runtimeHome)
                            .redirectErrorStream(true);
                    command.environment().put("HOME",runtimeHome.getAbsolutePath());
                    command.environment().put("XDG_CONFIG_HOME",new File(runtimeHome,".config").getAbsolutePath());
                    command.environment().put("XDG_CACHE_HOME",runtimeCache.getAbsolutePath());
                    command.environment().put("TMPDIR",context.getCacheDir().getAbsolutePath());
                    process=command.start();
                    checked++;
                    log.event("Endpoint "+checked+" • "+url+" • "+templateNames.size()+" configured templates");
                    String endpointStatus="incomplete";
                    StringBuilder errors=new StringBuilder();
                    // Read until Nuclei exits or the user cancels; no global execution deadline.
                    BufferedReader reader=new BufferedReader(new InputStreamReader(process.getInputStream()));
                    while(!cancelled.getAsBoolean()) {
                        log.tick();
                        if(!reader.ready()) {
                            if(process.isAlive()) { Thread.sleep(50);continue; }
                            // Drain remaining buffered output after process exit.
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
                                    NucleiTemplates.findingEvidence(severity,description));
                            found++;
                            log.event("Match • "+severity+" • "+title+" • verification required");
                        } catch(org.json.JSONException ignored) {
                            log.event("Diagnostic: "+line);
                            if(errors.length()<1200)errors.append(line,0,Math.min(line.length(),300)).append(" | ");
                        }
                    }
                    if(cancelled.getAsBoolean()) {
                        failed++;endpointStatus="cancelled";process.destroyForcibly();
                        notices.add("Nuclei cancelled for "+url+".");
                    } else if(process.waitFor()!=0) {
                        failed++;endpointStatus="failed";
                        String detail=errors.length()==0?"no diagnostic output":ToolProgress.clean(errors.toString());
                        notices.add("Nuclei failed for "+url+" (exit "+process.exitValue()+"): "+detail);
                    } else {completed++;endpointStatus="completed";}
                    evidence.add(host,"Nuclei","endpoint:"+port,service.getValue()+" • "+endpointStatus+" • "+templateNames.size()+" configured templates");
                    log.event(url+" • "+endpointStatus+" • "+found+" total matches");
                    if(endpointStatus.equals("failed"))log.event("Exit "+process.exitValue()+": "+errors);
                } catch(Exception error) {
                    failed++;
                    log.event("Failed • "+url+" • "+error.getMessage());
                    evidence.add(host,"Nuclei","endpoint:"+port,service.getValue()+" • failed");
                    notices.add("Nuclei "+host+": "+DeviceEvidence.clean(error.getMessage()==null?error.toString():error.getMessage()));
                } finally {if(process!=null)process.destroyForcibly();}
            }
        }
        notices.add("Nuclei coverage: "+NucleiTemplates.summary(coverageMask)+". Configured templates are not a count of successful checks; no matches do not prove absence of vulnerabilities.");
        notices.add("Nuclei: "+checked+" web endpoints attempted; "+completed+" completed; "+failed+" failed/incomplete; "+found+" findings; "+templateNames.size()+" bundled templates (verification required).");
        if(checked==0)notices.add("Nuclei skipped: no HTTP/HTTPS endpoints confirmed by HTTP probes or Nmap.");
        log.event((cancelled.getAsBoolean()?"Cancelled":"Finished")+" • "+completed+" completed • "+failed+" failed/incomplete • "+found+" matches");
        if(checked==0)log.event("No confirmed HTTP/HTTPS endpoints to check");
        log.flush();
        return notices;
    }
}
