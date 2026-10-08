package com.netmap.android;

import java.io.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.concurrent.*;

/** Optional Nmap process adapter. Only literal validated local targets are accepted. */
final class NmapRunner {
    interface Launcher{Process start(List<String> command)throws IOException;} private final Launcher launcher;
    private final java.util.function.BooleanSupplier cancelled;
    private final NmapCommands templates;
    private final java.util.function.Consumer<Execution> completed;
    static final class Execution {
        final List<String> command;
        final String profile, stdout, stderr, error;
        final Integer exitCode;
        final long durationMs;
        Execution(List<String> command,String profile,String stdout,String stderr,String error,Integer exitCode,long durationMs) {
            this.command=Collections.unmodifiableList(new ArrayList<>(command));this.profile=profile;
            this.stdout=stdout;this.stderr=stderr;this.error=error;this.exitCode=exitCode;this.durationMs=durationMs;
        }
        String text() {
            return "Profile: "+profile+"\nCommand (argv): "+command+"\nExit code: "+(exitCode==null?"unavailable":exitCode)
                +"\nDuration: "+durationMs+" ms\nStatus: "+(error.isEmpty()?"Process completed":error)
                +"\n\nNMAP OUTPUT (TEXT)\n"+stdout+"\n\nERRORS / WARNINGS\n"+stderr;
        }
    }
    private static final class Capture {
        private final ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        private final int limit;
        private boolean truncated;
        Capture(int limit){this.limit=limit;}
        void read(InputStream input)throws IOException {
            byte[] buffer=new byte[8192];int count;
            while((count=input.read(buffer))!=-1) synchronized(this) {
                int accepted=Math.min(count,limit-bytes.size());
                bytes.write(buffer,0,accepted);if(accepted<count)truncated=true;
            }
        }
        synchronized boolean truncated(){return truncated;}
        synchronized String text(){return new String(bytes.toByteArray(),StandardCharsets.UTF_8)+(truncated?"\n[Output truncated: configured byte limit exceeded]":"");}
    }
    NmapRunner(NmapCommands templates,Launcher launcher){this(templates,launcher,()->false);}
    NmapRunner(NmapCommands templates,Launcher launcher,java.util.function.BooleanSupplier cancelled){this(templates,launcher,cancelled,result->{});}
    NmapRunner(NmapCommands templates,Launcher launcher,java.util.function.BooleanSupplier cancelled,java.util.function.Consumer<Execution> completed) {
        this.templates=Objects.requireNonNull(templates);this.launcher=launcher;this.cancelled=cancelled;this.completed=completed;
    }
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
        File xmlOutput=File.createTempFile("nmap-", ".xml",new File(dataDir));
        values.put("xmlOutput",xmlOutput.getAbsolutePath());
        final List<String> command;
        try {command=templates.command(profile,host,values);}
        catch(RuntimeException invalidCommand) {xmlOutput.delete();throw invalidCommand;}
        long started=System.nanoTime();
        Process process=null;Integer exitCode=null;String error="";
        Capture stdout=new Capture(templates.maximumOutputBytes),stderr=new Capture(templates.maximumOutputBytes);
        ExecutorService readers=Executors.newFixedThreadPool(2);
        Future<?> out=null,err=null;
        try {
            if(cancelled.getAsBoolean())throw new IOException("Nmap cancelled");
            if(launcher!=null)process=launcher.start(command);
            else {
                ProcessBuilder builder=new ProcessBuilder(command); // stderr must never enter the XML parser.
                builder.environment().putAll(templates.environment(values));process=builder.start();
            }
            Process active=process;
            out=readers.submit(()->{stdout.read(active.getInputStream());return null;});
            err=readers.submit(()->{stderr.read(active.getErrorStream());return null;});
            awaitExit(process,profile.processTimeoutSeconds,"Nmap timed out");
            exitCode=process.exitValue();
            out.get(templates.outputReadTimeoutSeconds,TimeUnit.SECONDS);
            err.get(templates.outputReadTimeoutSeconds,TimeUnit.SECONDS);
            if(exitCode!=0)throw new IOException("Nmap exited with code "+exitCode+": "+DeviceEvidence.clean(stderr.text()));
            if(stdout.truncated()||stderr.truncated())throw new IOException("Nmap output exceeds configured limit");
            // XML remains machine-readable; stdout is Nmap's normal human-readable output.
            try(InputStream input=new FileInputStream(xmlOutput)) {
                return readBounded(input,templates.maximumOutputBytes);
            }
        } catch(Exception failure) {
            error=failure.getMessage()==null?failure.getClass().getSimpleName():failure.getMessage();
            throw failure;
        } finally {
            if(process!=null) {
                process.destroyForcibly();
                // Give both pipe readers a bounded chance to capture output emitted before failure.
                for(Future<?> task:Arrays.asList(out,err)) if(task!=null)try {task.get(250,TimeUnit.MILLISECONDS);} catch(Exception ignored) { }
                try {process.getInputStream().close();}catch(IOException ignored) { }
                try {process.getErrorStream().close();}catch(IOException ignored) { }
                try {process.getOutputStream().close();}catch(IOException ignored) { }
            }
            if(out!=null)out.cancel(true);if(err!=null)err.cancel(true);readers.shutdownNow();
            xmlOutput.delete();
            completed.accept(new Execution(command,profile==templates.services?"Service detection":"Vulnerability detection",
                    stdout.text(),stderr.text(),error,exitCode,TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started)));
        }
    }

    static String readBounded(InputStream input,int max)throws IOException{ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int total=0,read;while((read=input.read(buffer))!=-1){total+=read;if(total>max)throw new IOException("Nmap output exceeds limit");out.write(buffer,0,read);}return out.toString(StandardCharsets.UTF_8.name());}
}
