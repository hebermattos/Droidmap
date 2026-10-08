package com.netmap.android;

import java.util.*;

public final class NmapCommandTests {
    private static int assertions;
    private static void check(boolean ok, String message) { assertions++; if (!ok) throw new AssertionError(message); }
    private static void rejects(Runnable action) {
        try { action.run(); throw new AssertionError("Expected invalid template rejection"); }
        catch (IllegalArgumentException expected) { assertions++; }
    }
    private static Map<String,String> bindings(NmapCommands template,String binary,String data,String host,Collection<Integer> ports,int timeout) {
        Map<String,String> values=template.bindings(binary,data,host,ports,timeout);
        values.put("xmlOutput","/data/temporary scan.xml");return values;
    }
    public static void main(String[] args) {
        NmapCommands template = TestNmapTemplates.load();
        Map<String,String> values = bindings(template,"/data/lib/libnmap.so", "/data/nmap-data", "192.168.0.109", List.of(80,443), 200);
        List<String> command = template.command(template.services, "192.168.0.109", values);
        check(command.get(command.indexOf("-oN")+1).equals("-"),"Normal text is explicitly sent to stdout");
        check(command.get(command.indexOf("-oX")+1).equals("/data/temporary scan.xml"),"XML file is separate from readable stdout and remains one argv token");
        check(command.get(0).equals("/data/lib/libnmap.so"), "Select runtime binary");
        check(command.contains("80,443") && command.contains("200ms"), "Bind ports and timeout");
        check(!command.contains("-6") && !command.contains("-e"), "IPv4 omits IPv6 flags");
        check(command.get(command.indexOf("--datadir")+1).equals("/data/nmap-data"), "Service scan explicitly selects installed NSE data");
        check(template.environment(values).get("NMAPDIR").equals("/data/nmap-data"), "Bind environment");
        values = bindings(template,"nmap", "data", "fe80::10%wlan0", List.of(443), 99);
        command = template.command(template.services, "fe80::10%wlan0", values);
        check(command.contains("-6") && command.contains("-e") && command.contains("wlan0"), "Apply IPv6 conditional argument groups");
        check(command.get(command.size()-1).equals("fe80::10"), "Strip zone from literal target");
        check(command.contains("100ms"), "Clamp minimum timeout");
        check(template.command(template.services, "fd00::10", bindings(template,"nmap","data","fd00::10",List.of(80),4000)).contains("3000ms"), "Clamp maximum timeout");
        List<String> vuln = template.command(template.vulnerabilities, "192.168.0.109", bindings(template,"nmap","data","192.168.0.109",List.of(443),200));
        check(vuln.get(vuln.indexOf("--script")+1).equals("(vuln and safe) and not brute and not dos and not intrusive and not exploit"), "Keep NSE expression as one argv token");
        check(vuln.get(vuln.indexOf("--datadir")+1).equals("data"), "Vulnerability scan explicitly selects installed NSE data");
        check(vuln.contains("443"), "Bind confirmed open ports");
        check(vuln.contains("-sV") && vuln.contains("--version-light"), "Detect actual services before vulnerability script rules, including nonstandard ports");
        NmapCommands.Profile changed = new NmapCommands.Profile(List.of("--version-all","--host-timeout","25s","-p","{ports}","{host}"),42);
        check(template.command(changed,"192.168.0.109",bindings(template,"nmap","data","192.168.0.109",List.of(80),200)).contains("25s"), "Edited profile arguments control command");
        check(changed.processTimeoutSeconds==42, "Edited profile controls process deadline");
        rejects(() -> new NmapCommands.Profile(List.of("{unknown}"),20));
        rejects(() -> new NmapCommands.Profile(List.of("{host"),20));
        rejects(() -> new NmapCommands.Profile(List.of("-n"),0));
        rejects(() -> bindings(template,"nmap","data","8.8.8.8",List.of(80),200));
        rejects(() -> bindings(template,"nmap","data","192.168.0.0/24",List.of(80),200));
        rejects(() -> bindings(template,"nmap","data","192.168.0.109",List.of(0),200));
        check(NmapCommands.expand("{dataDir}", Map.of("dataDir","/data/with $ and spaces")).equals("/data/with $ and spaces"), "Literal replacement retains shell metacharacters as data");
        System.out.println("PASS: "+assertions+" Nmap command template assertions");
    }
}

