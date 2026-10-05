package com.netmap.android;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;

public class NmapXmlParserTest {
    @Test public void parsesOpenServiceEvidence() throws Exception {
        DeviceEvidence evidence=new DeviceEvidence(Collections.singleton("192.168.1.10"));
        String xml="<?xml version=\"1.0\"?><nmaprun><host><address addr=\"192.168.1.10\" addrtype=\"ipv4\"/><hostnames><hostname name=\"nas.lan\"/></hostnames><ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/><service name=\"ssh\" product=\"OpenSSH\" version=\"9.6\"/></port></ports></host></nmaprun>";
        NmapXmlParser.parse(xml,evidence);
        List<DeviceEvidence.Observation> items=evidence.observations("192.168.1.10");
        assertTrue(items.stream().anyMatch(x->x.field.equals("openPort") && x.value.equals("22/tcp")));
        assertTrue(items.stream().anyMatch(x->x.field.equals("serviceName") && x.value.equals("ssh")));
        assertTrue(items.stream().anyMatch(x->x.field.equals("banner") && x.value.equals("OpenSSH 9.6")));
        assertTrue(items.stream().anyMatch(x->x.field.equals("dnsHostname") && x.value.equals("nas.lan")));
        assertTrue(items.stream().anyMatch(x->x.source.equals("Nmap") && x.field.equals("openPort")));
        assertTrue(items.stream().anyMatch(x->x.source.equals("Nmap service 22") && x.field.equals("banner")));
    }
    @Test public void parsesIpv6ServiceEvidence() throws Exception {
        String ip="fd00::10";
        DeviceEvidence evidence=new DeviceEvidence(Collections.singleton(ip));
        String xml="<?xml version=\"1.0\"?><nmaprun><host><address addr=\"fd00::10\" addrtype=\"ipv6\"/><ports><port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/><service name=\"https\"/></port></ports></host></nmaprun>";
        NmapXmlParser.parse(xml,evidence);
        assertTrue(evidence.observations(ip).stream().anyMatch(x->x.field.equals("openPort") && x.value.equals("443/tcp")));
    }
    @Test public void rejectsDoctype() throws Exception {
        try {
            NmapXmlParser.parse("<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><nmaprun/>",new DeviceEvidence(Collections.singleton("192.168.1.1")));
            fail("DOCTYPE must be rejected");
        } catch(Exception expected) { }
    }
    @Test public void parsesSafeVulnerabilityScriptOutput() throws Exception {
        String ip="192.168.1.10"; DeviceEvidence evidence=new DeviceEvidence(Collections.singleton(ip));
        String xml="<?xml version=\"1.0\"?><nmaprun><host><address addr=\"192.168.1.10\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/><script id=\"ssl-poodle\" output=\"VULNERABLE: test finding\"/></port></ports></host></nmaprun>";
        NmapXmlParser.parseVulnerabilities(xml,evidence);
        assertTrue(evidence.observations(ip).stream().anyMatch(x->x.source.equals("Nmap vulnerabilities") && x.field.contains("443") && x.value.contains("VULNERABLE")));
    }
}
