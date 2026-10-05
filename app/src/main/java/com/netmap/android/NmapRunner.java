package com.netmap.android;

import java.io.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.concurrent.*;

/** Optional Nmap process adapter. Only literal validated local targets are accepted. */
final class NmapRunner {
    interface Launcher{Process start(List<String> command)throws IOException;} private final Launcher launcher;
    NmapRunner(){launcher=null;} NmapRunner(Launcher launcher){this.launcher=launcher;}
    String scan(String binary,String dataDir,String host,Collection<Integer> ports,int timeoutMs)throws Exception{
        List<String> validated=ScanPlan.parseHosts(host);if(validated.size()!=1||!validated.get(0).equals(host))throw new IllegalArgumentException("Nmap target must be a local literal IP address");
        if(binary==null||binary.trim().isEmpty())throw new IllegalArgumentException("Missing Nmap binary");
        StringBuilder selected=new StringBuilder();for(Integer port:ports){if(port==null||port<1||port>65535)throw new IllegalArgumentException("Invalid Nmap port");if(selected.length()>0)selected.append(',');selected.append(port);}
        List<String> command=new ArrayList<>();command.add(binary);if(ScanPlan.isIpv6(host))command.add("-6");
        Collections.addAll(command,"-sT","-sV","-Pn","--version-light","--host-timeout","15s","--max-retries","1","--max-rtt-timeout",Math.max(100,Math.min(3000,timeoutMs))+"ms","-p",selected.toString(),"-oX","-",host);
        Process process;if(launcher!=null)process=launcher.start(command);else{ProcessBuilder builder=new ProcessBuilder(command).redirectErrorStream(true);builder.environment().put("NMAPDIR",dataDir);builder.environment().put("LD_LIBRARY_PATH",new File(binary).getParent());process=builder.start();}
        ExecutorService reader=Executors.newSingleThreadExecutor();Future<String> output=reader.submit(()->readBounded(process.getInputStream(),1024*1024));
        try{if(!process.waitFor(20,TimeUnit.SECONDS)){process.destroyForcibly();throw new IOException("Nmap timed out");}String xml=output.get(2,TimeUnit.SECONDS);if(process.exitValue()!=0)throw new IOException("Nmap exited with code "+process.exitValue());return xml;}finally{process.destroy();output.cancel(true);reader.shutdownNow();}
    }
    String vulnerabilityScan(String binary,String dataDir,String host,Collection<Integer> ports,int timeoutMs)throws Exception{
        List<String> validated=ScanPlan.parseHosts(host);if(validated.size()!=1||!validated.get(0).equals(host))throw new IllegalArgumentException("Nmap target must be a local literal IP address");
        StringBuilder selected=new StringBuilder();for(Integer port:ports){if(port==null||port<1||port>65535)throw new IllegalArgumentException("Invalid Nmap port");if(selected.length()>0)selected.append(',');selected.append(port);}if(selected.length()==0)return "";
        List<String> command=new ArrayList<>();command.add(binary);if(ScanPlan.isIpv6(host))command.add("-6");
        Collections.addAll(command,"-sT","-Pn","--script","(vuln and safe) and not brute and not dos and not intrusive and not exploit","--script-timeout","10s","--host-timeout","30s","--max-retries","1","-p",selected.toString(),"-oX","-",host);
        Process process;if(launcher!=null)process=launcher.start(command);else{ProcessBuilder builder=new ProcessBuilder(command).redirectErrorStream(true);builder.environment().put("NMAPDIR",dataDir);builder.environment().put("LD_LIBRARY_PATH",new File(binary).getParent());process=builder.start();}
        ExecutorService reader=Executors.newSingleThreadExecutor();Future<String> output=reader.submit(()->readBounded(process.getInputStream(),1024*1024));
        try{if(!process.waitFor(35,TimeUnit.SECONDS)){process.destroyForcibly();throw new IOException("Nmap vulnerability scan timed out");}String xml=output.get(2,TimeUnit.SECONDS);if(process.exitValue()!=0)throw new IOException("Nmap vulnerability scan exited with code "+process.exitValue());return xml;}finally{process.destroy();output.cancel(true);reader.shutdownNow();}
    }
    static String readBounded(InputStream input,int max)throws IOException{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int total=0,read;while((read=input.read(buffer))!=-1){total+=read;if(total>max)throw new IOException("Nmap output exceeds limit");out.write(buffer,0,read);}return out.toString(StandardCharsets.UTF_8.name());}
}