package com.netmap.android;

import java.util.*;

/** Plain Java regressions for sourced MAC observations and Wi-Fi target filtering. */
public final class MacAddressTests {
    private static int assertions;
    private static void check(boolean ok, String message) {
        assertions++;
        if (!ok) throw new AssertionError(message);
    }
    public static void main(String[] args) throws Exception {
        check(MacAddresses.normalize("ce:24:04:6a:12:34").equals("CE:24:04:6A:12:34"), "Normalize MAC");
        check(MacAddresses.kind("CE:24:04:6A:12:34").startsWith("Locally"), "Local bit does not prove randomization");
        check(MacAddresses.kind("00:11:22:33:44:55").startsWith("Universally"), "Universal bit");
        for (String bad : Arrays.asList(null, "", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01", "02:00:00:00:00:00", "AA-BB-CC-DD-EE-FF", "CE:24:04:6A:12", "CE:24:04:6A:12:GG"))
            check(MacAddresses.normalize(bad).isEmpty(), "Reject invalid/group/placeholder MAC");
        String ip = "192.168.0.109";
        DeviceEvidence evidence = new DeviceEvidence(List.of(ip, "10.0.0.10"));
        String line = ip + " dev wlan0 lladdr ce:24:04:6a:12:34 STALE";
        Ipv4MacDiscovery.recordLine(line, "wlan0", h -> h.startsWith("192.168.0."), evidence, false);
        check(DeviceEvidence.first(evidence.observations(ip), "neighborMac").equals("CE:24:04:6A:12:34"), "Capture neighbor MAC");
        check(DeviceEvidence.first(evidence.observations(ip), "neighborState").equals("STALE"), "Retain cached state");
        check(DeviceEvidence.first(evidence.observations(ip), "reachabilityNote").contains("unverified"), "Do not claim current reachability");
        int count = evidence.observations(ip).size();
        for (String invalid : List.of(line.replace("wlan0", "rmnet0"), line.replace("STALE", "FAILED"), line.replace("STALE", "INCOMPLETE"), line.replace("STALE", "UNKNOWN"), line.replace("ce:24:04:6a:12:34", "00:00:00:00:00:00")))
            Ipv4MacDiscovery.recordLine(invalid, "wlan0", h -> true, evidence, false);
        check(evidence.observations(ip).size() == count, "Reject wrong interface, state and MAC");
        Ipv4MacDiscovery.recordLine(line.replace(ip, "192.168.0.110"), "wlan0", h -> true, evidence, false);
        check(!evidence.hasObservations("192.168.0.110"), "No expansion of selected IPv4 targets");
        Ipv4MacDiscovery.recordLine(line.replace(ip, "10.0.0.10"), "wlan0", h -> false, evidence, false);
        check(!evidence.hasObservations("10.0.0.10"), "Reject off-link target");
        Ipv4MacDiscovery.recordLine(ip + " 0x1 0x2 ce:24:04:6a:12:34 * wlan0", "wlan0", h -> true, evidence, true);
        check(MacAddresses.observations(evidence.observations(ip)).size() == 2, "Keep both source observations");
        DeviceEvidence rejected = new DeviceEvidence(List.of(ip));
        for (String row : List.of(ip + " 0x1 0x0 ce:24:04:6a:12:34 * wlan0", ip + " 0x2 0x2 ce:24:04:6a:12:34 * wlan0", ip + " 0x1 0x2 ce:24:04:6a:12:34 * rmnet0", "IP address HW type Flags HW address Mask Device", ip + " invalid invalid ce:24:04:6a:12:34 * wlan0"))
            Ipv4MacDiscovery.recordLine(row, "wlan0", h -> true, rejected, true);
        check(!rejected.hasObservations(ip), "Reject incomplete/non-Ethernet ARP rows and headers");
        String xml = "<nmaprun><host><address addr='" + ip + "' addrtype='ipv4'/><address addr='00:11:22:33:44:55' addrtype='mac'/></host></nmaprun>";
        NmapXmlParser.parse(xml, evidence);
        check(MacAddresses.observations(evidence.observations(ip)).size() == 3, "Retain Nmap MAC with its source");
        NmapXmlParser.parse(xml.replace(ip, "192.168.0.110"), evidence);
        check(!evidence.hasObservations("192.168.0.110"), "Ignore off-target Nmap MAC");
        evidence.add(ip, "NetBIOS", "reportedMac", "CE:24:04:6A:12:34");
        evidence.add(ip, "Other", "reportedMac", "02:00:00:00:00:00");
        check(MacAddresses.observations(evidence.observations(ip)).size() == 4, "Preserve NetBIOS and filter placeholder");
        check(Ipv4MacDiscovery.collect("wlan0", h -> true, evidence, () -> true, true).isEmpty(), "Cancelled collector skips processes and files");
        System.out.println("PASS: " + assertions + " MAC address assertions");
    }
}
