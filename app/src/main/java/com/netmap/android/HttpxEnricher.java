package com.netmap.android;

import android.content.Context;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.function.*;

/** One explicit HTTPX process for one Discovery-authorized web endpoint. */
final class HttpxEnricher {
    private HttpxEnricher() {}
    static List<String> enrich(Context context,DeviceEvidence evidence,String ip,int port,
            BooleanSupplier cancelled,Consumer<String> progress) {
        List<String> notices=new ArrayList<>();
        ToolProgress log=new ToolProgress("HTTPX",progress);
        String source="HTTPX tcp/"+port,status="failed";
        Process process=null;File output=null;
        try {
            String scheme=WebEndpoints.scheme(evidence.snapshot().getOrDefault(ip,Collections.emptyList()),port);
            String url=WebEndpoints.url(scheme,ip,port);
            log.event("Preparing web analysis • "+url);
            File binary=new File(context.getApplicationInfo().nativeLibraryDir,"libhttpx.so");
            if(!binary.isFile())throw new IOException("Android-compatible HTTPX runtime is not bundled");
            File home=new File(context.getFilesDir(),"httpx-home");
            if(!home.isDirectory()&&!home.mkdirs())throw new IOException("Cannot create writable HTTPX directory");
            output=File.createTempFile("httpx-",".jsonl",context.getCacheDir());
            ProcessBuilder command=new ProcessBuilder(binary.getAbsolutePath(),"-u",url,"-json","-silent","-no-color",
                    "-no-stdin","-disable-update-check","-no-fallback-scheme","-cdn=false",
                    "-title","-status-code","-web-server","-tech-detect","-location","-content-type","-response-time",
                    "-tls-grab","-threads","1","-rate-limit","2","-timeout","10","-retries","0",
                    "-response-size-to-read","262144","-response-size-to-save","0")
                    .directory(home).redirectErrorStream(true).redirectOutput(output);
            Map<String,String> env=command.environment();
            env.put("HOME",home.getAbsolutePath());env.put("XDG_CONFIG_HOME",home.getAbsolutePath());
            env.put("XDG_CACHE_HOME",context.getCacheDir().getAbsolutePath());env.put("TMPDIR",context.getCacheDir().getAbsolutePath());
            // A device-wide proxy must not redirect private endpoint analysis elsewhere.
            for(String key:new ArrayList<>(env.keySet()))if(key.toLowerCase(Locale.ROOT).endsWith("_proxy"))env.remove(key);
            if(cancelled.getAsBoolean()) {status="cancelled";return notices;}
            process=command.start();process.getOutputStream().close();
            long started=System.nanoTime();
            log.event("Reading web metadata • redirects disabled • TLS validation enabled");
            while(process.isAlive()&&!cancelled.getAsBoolean()) {
                if(output.length()>524288)throw new IOException("HTTPX output exceeded 512 KiB");
                if(System.nanoTime()-started>45_000_000_000L)throw new IOException("HTTPX exceeded the 45 second runtime budget");
                log.tick();Thread.sleep(50);
            }
            if(cancelled.getAsBoolean()) {status="cancelled";return notices;}
            if(output.length()>524288)throw new IOException("HTTPX output exceeded 512 KiB");
            boolean received=false;
            List<String> lines=Files.readAllLines(output.toPath(),StandardCharsets.UTF_8);
            String diagnostic="";
            for(String line:lines) {
                try {received |= HttpxResult.record(line,url,ip,port,evidence);}
                catch(org.json.JSONException ignored) {
                    if(diagnostic.isEmpty())diagnostic=ToolProgress.clean(line);
                }
            }
            if(process.exitValue()!=0||!received)
                throw new IOException("HTTPX exit "+process.exitValue()+": "+(diagnostic.isEmpty()
                        ?"No valid HTTP response; check connectivity and HTTPS certificate trust/name":diagnostic));
            status="completed";
            notices.add("HTTPX reads web metadata only. Redirect destinations are reported without being visited; technologies are estimates.");
        } catch(Exception error) {
            status=cancelled.getAsBoolean()?"cancelled":"failed";
            notices.add("HTTPX "+ip+":"+port+": "+DeviceEvidence.clean(error.getMessage()));
            log.event(notices.get(notices.size()-1));
        } finally {
            if(process!=null)process.destroyForcibly();
            if(output!=null&&!output.delete())output.deleteOnExit();
            if(cancelled.getAsBoolean())status="cancelled";
            evidence.add(ip,source,"scanStatus",status);
            log.event(status);log.flush();
        }
        return notices;
    }
}
