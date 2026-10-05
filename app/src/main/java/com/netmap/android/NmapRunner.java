package com.netmap.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/** Optional Nmap process adapter. Only literal validated targets are accepted. */
final class NmapRunner {
    interface Launcher { Process start(List<String> command) throws IOException; }
    private final Launcher launcher;
    NmapRunner() { this(command -> new ProcessBuilder(command).redirectErrorStream(true).start()); }
    NmapRunner(Launcher launcher) { this.launcher=launcher; }

    String scan(String binary,String host,Collection<Integer> ports,int timeoutMs) throws Exception {
        if(!ScanPlan.isPrivateIpv4(host)) throw new IllegalArgumentException("Nmap target must be a private IPv4 address");
        if(binary==null || binary.trim().isEmpty()) throw new IllegalArgumentException("Missing Nmap binary");
        StringBuilder selected=new StringBuilder();
        for(Integer port:ports) {
            if(port==null || port<1 || port>65535) throw new IllegalArgumentException("Invalid Nmap port");
            if(selected.length()>0) selected.append(',');
            selected.append(port);
        }
        List<String> command=Arrays.asList(binary,"-sT","-sV","-Pn","--version-light","--host-timeout","15s",
                "--max-retries","1","--max-rtt-timeout",Math.max(100,Math.min(3000,timeoutMs))+"ms",
                "-p",selected.toString(),"-oX","-",host);
        Process process=launcher.start(command);
        ExecutorService reader=Executors.newSingleThreadExecutor();
        Future<String> output=reader.submit(() -> readBounded(process.getInputStream(),1024*1024));
        try {
            if(!process.waitFor(20,TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IOException("Nmap timed out"); }
            String xml=output.get(2,TimeUnit.SECONDS);
            if(process.exitValue()!=0) throw new IOException("Nmap exited with code "+process.exitValue());
            return xml;
        } finally { process.destroy(); output.cancel(true); reader.shutdownNow(); }
    }

    static String readBounded(InputStream input,int max) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream(); byte[] buffer=new byte[8192]; int total=0,read;
        while((read=input.read(buffer))!=-1) {
            total+=read; if(total>max) throw new IOException("Nmap output exceeds limit");
            out.write(buffer,0,read);
        }
        return out.toString(StandardCharsets.UTF_8.name());
    }
}
