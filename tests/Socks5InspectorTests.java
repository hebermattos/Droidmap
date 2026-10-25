package com.netmap.android;
import java.util.*;
public final class Socks5InspectorTests {
    private static void check(boolean value){if(!value)throw new AssertionError();}
    public static void main(String[] args)throws Exception {
        check(Socks5Inspector.classify(5,0).contains("forwarding NOT verified"));
        check(Socks5Inspector.classify(5,2).contains("authentication requested"));
        check(Socks5Inspector.classify(5,255).contains("no acceptable"));
        check(Socks5Inspector.classify(4,0).startsWith("Unknown protocol"));
        String xml="<nmaprun><host><address addr=\"192.168.1.10\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"8888\"><state state=\"open\"/><service name=\"tcpwrapped\"/></port></ports></host></nmaprun>";
        DeviceEvidence ev=new DeviceEvidence(List.of("192.168.1.10"));
        NmapXmlParser.parse(xml,ev);
        check(ev.observations("192.168.1.10").stream().anyMatch(x->x.field.equals("identification")&&x.value.contains("protocol not confirmed")));
        System.out.println("Socks5InspectorTests passed");
    }
}
