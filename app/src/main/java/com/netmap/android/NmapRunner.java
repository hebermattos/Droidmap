package com.netmap.android;

import java.io.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.concurrent.*;

/** Optional Nmap process adapter. Only literal validated local targets are accepted. */
final class NmapRunner {
    interface Launcher{Process start(List<String> command)throws IOException;} private final Launcher launcher;
    private final java.util.function.BooleanSupplier cancelled;
    private final NmapCommands templates;
    NmapRunner(NmapCommands templates,Launcher launcher){this(templates,launcher,()->false);}
    NmapRunner(NmapCommands templates,Launcher launcher,java.util.function.BooleanSupplier cancelled){this.templates=Objects.requireNonNull(templates);this.launcher=launcher;this.cancelled=cancelled;}
    private void awaitExit(Process process,int seconds,String timeoutMessage)throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds);
        while(!process.waitFor(100,TimeUnit.MILLISECONDS)) {
            if(cancelled.getAsBoolean()||Thread.currentThread().isInterrupted()) throw new IOException("Nmap cancelled");
            if(System.nanoTime()>=deadline) throw new IOException(timeoutMessage);
        }
        if(cancelled.getAsBoolean()) throw new IOException("Nmap cancelled");
    }
    String scan(String binary,String dataDir,String host,Collection<Integer> ports,int timeoutMs)throws Exception{
        if(ports.isEmpty())throw new IllegalArgumentException("Missing Nmap ports");
        return run(templates.services,binary,dataDir,host,ports,timeoutMs);
    }
    String vulnerabilityScan(String binary,String dataDir,String host,Collection<Integer> ports,int timeoutMs)throws Exception{
        if(ports.isEmpty())return "";
        return run(templates.vulnerabilities,binary,dataDir,host,ports,timeoutMs);
    }
    private String run(NmapCommands.Profile profile,String binary,String dataDir,String host,Collection<Integer> ports,int timeoutMs)throws Exception{
        Map<String,String> values=templates.bindings(binary,dataDir,host,ports,timeoutMs);
        List<String> command=templates.command(profile,host,values);
        if(cancelled.getAsBoolean())throw new IOException("Nmap cancelled");
        Process process;
        if(launcher!=null)process=launcher.start(command);
        else {
            ProcessBuilder builder=new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().putAll(templates.environment(values));
            process=builder.start();
        }
        ExecutorService reader=Executors.newSingleThreadExecutor();
        Future<String> output=reader.submit(()->readBounded(process.getInputStream(),templates.maximumOutputBytes));
        try {
            awaitExit(process,profile.processTimeoutSeconds,"Nmap timed out");
            String xml=output.get(templates.outputReadTimeoutSeconds,TimeUnit.SECONDS);
            if(process.exitValue()!=0)throw new IOException("Nmap exited with code "+process.exitValue());
            return xml;
        } finally {
            process.destroyForcibly();try{process.getInputStream().close();}catch(IOException ignored){}
            output.cancel(true);reader.shutdownNow();
        }
    }
    static String readBounded(InputStream input,int max)throws IOException{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int total=0,read;while((read=input.read(buffer))!=-1){total+=read;if(total>max)throw new IOException("Nmap output exceeds limit");out.write(buffer,0,read);}return out.toString(StandardCharsets.UTF_8.name());}
}