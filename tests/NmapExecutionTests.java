package com.netmap.android;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/** Real local subprocesses exercise diagnostics without scanning a network. */
public final class NmapExecutionTests {
    private static int assertions;
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static NmapCommands templates(int max,int seconds) {
        NmapCommands base=TestNmapTemplates.load();
        return new NmapCommands(new NmapCommands.Profile(base.services.argv,seconds),base.vulnerabilities,
                base.ipv6Args,base.interfaceArgs,base.environment,max,1,100,3000);
    }
    private static NmapRunner runner(String script,int max,int seconds,AtomicReference<NmapRunner.Execution> capture) {
        return new NmapRunner(templates(max,seconds),command->new ProcessBuilder("/bin/sh","-c",script).start(),()->false,capture::set);
    }
    private static void scan(NmapRunner runner)throws Exception {runner.scan("nmap","data","192.168.1.10",List.of(80),200);}
    private static void fails(NmapRunner runner,String expected)throws Exception {
        try {scan(runner);throw new AssertionError("Expected "+expected);}catch(IOException error){check(error.getMessage().contains(expected),expected);}
    }
    public static void main(String[] args)throws Exception {
        AtomicReference<NmapRunner.Execution> capture=new AtomicReference<>();
        NmapRunner success=runner("printf '<nmaprun></nmaprun>'; printf 'warning: test\\n' >&2",1024,2,capture);
        String xml=success.scan("nmap","data","192.168.1.10",List.of(80),200);
        check(xml.equals("<nmaprun></nmaprun>"),"stderr must not corrupt XML");
        NmapXmlParser.parse(xml,new DeviceEvidence(List.of("192.168.1.10")));
        check(capture.get().stderr.equals("warning: test\n"),"preserve warning newlines");
        check(capture.get().exitCode==0&&capture.get().error.isEmpty(),"successful exit status");
        check(capture.get().command.contains("80")&&capture.get().command.contains("192.168.1.10"),"exact target argv retained");
        fails(runner("printf 'partial XML'; printf 'permission denied' >&2; exit 7",1024,2,capture),"code 7");
        check(capture.get().exitCode==7&&capture.get().stderr.equals("permission denied"),"nonzero exit retains stderr");
        check(capture.get().stdout.equals("partial XML"),"failed output retained");
        fails(new NmapRunner(templates(1024,1),command->{throw new IOException("Cannot execute binary");},()->false,capture::set),"Cannot execute");
        check(capture.get().exitCode==null&&capture.get().error.contains("Cannot execute"),"launch failure retained");
        fails(runner("printf 'before timeout'; exec sleep 5",1024,1,capture),"timed out");
        check(capture.get().stdout.equals("before timeout"),"timeout retains partial output");
        long started=System.nanoTime();
        NmapRunner cancelled=new NmapRunner(templates(1024,5),command->new ProcessBuilder("/bin/sh","-c","printf 'before cancel'; exec sleep 5").start(),
                ()->System.nanoTime()-started>200_000_000L,capture::set);
        fails(cancelled,"cancelled");
        check(capture.get().stdout.equals("before cancel")&&capture.get().durationMs<2000,"cancellation is prompt and retains output");
        fails(runner("printf '12345678901234567890'",8,2,capture),"limit");
        check(capture.get().stdout.startsWith("12345678")&&capture.get().stdout.contains("truncated"),"explicit stdout truncation");
        fails(runner("printf '<xml/>'; printf '12345678901234567890' >&2",8,2,capture),"limit");
        check(capture.get().stderr.contains("truncated"),"stderr bound enforced");
        scan(runner("i=0; while [ $i -lt 10000 ]; do printf '0123456789abcdef'; printf 'fedcba9876543210' >&2; i=$((i+1)); done",1048576,5,capture));
        check(capture.get().stdout.length()==160000&&capture.get().stderr.length()==160000,"both pipes drained concurrently");
        check(capture.get().text().contains("STDOUT (XML)")&&capture.get().text().contains("STDERR"),"diagnostic format");
        NmapRunner.Execution longOutput=capture.get();
        scan(runner("printf 'not XML'",1024,2,capture));
        try {NmapXmlParser.parse(capture.get().stdout,new DeviceEvidence(List.of("192.168.1.10")));throw new AssertionError("Invalid XML accepted");}
        catch(org.xml.sax.SAXException expected){check(capture.get().stdout.equals("not XML"),"XML parse failure retains raw response");}
        Path dir=Files.createTempDirectory("nmap-output-test");
        try {
            NmapOutputStore store=new NmapOutputStore(dir.toFile());
            String reference=store.save(longOutput);
            check(NmapOutputStore.read(dir.toFile(),reference).equals(longOutput.text()),"full output disk round trip");
            check(NmapOutputStore.read(dir.toFile(),reference).length()>300,"output not shortened to evidence limit");
            String second=new NmapOutputStore(dir.toFile()).save(capture.get());
            check(!reference.equals(second),"new scan does not overwrite old output");
            try {NmapOutputStore.read(dir.toFile(),"../escape.txt");throw new AssertionError("Traversal accepted");}
            catch(IOException expected){check(true,"invalid reference rejected");}
            Files.delete(dir.resolve("nmap-output").resolve(reference));
            try {NmapOutputStore.read(dir.toFile(),reference);throw new AssertionError("Missing file accepted");}
            catch(IOException expected){check(expected.getMessage().contains("no longer available"),"missing output reported");}
            DeviceEvidence evidence=new DeviceEvidence(List.of("192.168.1.10"));
            for(int i=0;i<48;i++)evidence.add("192.168.1.10","test","value","item"+i);
            evidence.nmapOutput("192.168.1.10","Nmap",second);
            evidence.nmapOutput("192.168.1.10","Nmap",second);
            evidence.nmapOutput("8.8.8.8","Nmap",second);
            evidence.nmapOutput("192.168.1.10","other",second);
            check(evidence.snapshot().get("192.168.1.10").size()==49,"reserved output reference survives full evidence capacity and deduplicates");
            check(evidence.snapshot().size()==1,"output reference obeys target scope");
            evidence.nmapStatus("192.168.1.10","Nmap","Running service detection");
            evidence.nmapStatus("192.168.1.10","Nmap","Completed");
            List<DeviceEvidence.Observation> observations=evidence.snapshot().get("192.168.1.10");
            check(observations.size()==50,"status has a reserved slot");
            check(observations.stream().filter(item->item.field.equals("scanStatus")).count()==1
                    &&DeviceEvidence.first(observations,"scanStatus").equals("Completed"),"running status replaced by completion");
            NmapRunner.Execution large=new NmapRunner.Execution(List.of("nmap"),"Service detection",
                    "x".repeat(1024*1024),"y".repeat(1024*1024),"",0,1);
            NmapOutputStore limited=new NmapOutputStore(dir.toFile());
            for(int i=0;i<15;i++)limited.save(large);
            try {limited.save(large);throw new AssertionError("Run budget exceeded");}
            catch(IOException expected){check(expected.getMessage().contains("storage limit"),"per-run storage budget enforced");}
            NmapRunner.Execution tooLarge=new NmapRunner.Execution(List.of("nmap"),"Service detection",
                    "x".repeat(NmapOutputStore.FILE_LIMIT),"","",0,1);
            try {limited.save(tooLarge);throw new AssertionError("File budget exceeded");}
            catch(IOException expected){check(true,"per-file budget enforced");}
            for(int i=0;i<9;i++)new NmapOutputStore(dir.toFile()).save(capture.get());
            check(Objects.requireNonNull(dir.resolve("nmap-output").toFile().listFiles()).length<=8,"old scan directories pruned");
            long total;
            try(java.util.stream.Stream<Path> paths=Files.walk(dir)) {
                total=paths.filter(Files::isRegularFile).mapToLong(path->{try{return Files.size(path);}catch(IOException error){throw new UncheckedIOException(error);}}).sum();
            }
            check(total<=NmapOutputStore.STORAGE_LIMIT,"total diagnostics storage bounded");
        } finally {
            try(java.util.stream.Stream<Path> paths=Files.walk(dir)){paths.sorted(Comparator.reverseOrder()).forEach(path->{try{Files.delete(path);}catch(IOException error){throw new UncheckedIOException(error);}});}
        }
        // The host JDK accepts Xerces flags; reproduce Android's factory contract explicitly.
        String factoryProperty="javax.xml.parsers.DocumentBuilderFactory";
        String previousFactory=System.getProperty(factoryProperty);
        System.setProperty(factoryProperty,AndroidDocumentBuilderFactory.class.getName());
        try {
            String host="192.168.1.10";
            String response="<?xml version=\"1.0\"?><!DOCTYPE nmaprun><nmaprun><host>"
                    +"<address addr=\"192.168.1.10\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"80\">"
                    +"<state state=\"open\"/><service name=\"http\"/><script id=\"test\" output=\"a &amp; b\"/>"
                    +"</port></ports></host></nmaprun>";
            DeviceEvidence parsed=new DeviceEvidence(List.of(host));
            NmapXmlParser.parse(response,parsed);
            NmapXmlParser.parseVulnerabilities(response,parsed,List.of(80));
            check(parsed.observations(host).stream().anyMatch(item->item.field.equals("openPort")&&item.value.equals("80/tcp")),
                    "service XML parses without unsupported Android factory flags");
            check(parsed.observations(host).stream().anyMatch(item->item.source.equals("Nmap vulnerabilities")&&item.value.equals("a & b")),
                    "vulnerability XML and predefined entities parse on Android-compatible factory");
            for(String bad:List.of(
                    "<!DOCTYPE nmaprun SYSTEM \"file:///etc/passwd\"><nmaprun/>",
                    "<!DOCTYPE nmaprun [<!ENTITY e SYSTEM \"http://127.0.0.1:9/\">]><nmaprun>&e;</nmaprun>",
                    "<!DOCTYPE nmaprun [<!ENTITY e 'expanded'>]><nmaprun>&e;</nmaprun>",
                    "<other/>")) {
                try {NmapXmlParser.parse(bad,parsed);throw new AssertionError("Unsafe or non-Nmap XML accepted");}
                catch(org.xml.sax.SAXException expected){check(true,"invalid XML rejected before external entity resolution");}
                try {NmapXmlParser.parseVulnerabilities(bad,parsed,List.of(80));throw new AssertionError("Unsafe vulnerability XML accepted");}
                catch(org.xml.sax.SAXException expected){check(true,"vulnerability parser enforces the same XML policy");}
            }
        } finally {
            if(previousFactory==null)System.clearProperty(factoryProperty);else System.setProperty(factoryProperty,previousFactory);
        }
        System.out.println("PASS: "+assertions+" Nmap execution/output assertions");
    }
}
