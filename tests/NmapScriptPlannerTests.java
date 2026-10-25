package com.netmap.android;
import java.util.*;
public final class NmapScriptPlannerTests {
    static void check(boolean condition){if(!condition)throw new AssertionError();}
    public static void main(String[] args) {
        check(NmapScriptPlanner.failures("|_rpcinfo: ERROR: Script execution failed (use -d to debug)\n|_vmware-version: ERROR: Script execution failed", "").equals(List.of("rpcinfo","vmware-version")));
        check(NmapScriptPlanner.failures("normal success","").isEmpty());
        List<DeviceEvidence.Observation> observations=List.of(new DeviceEvidence.Observation("Nmap service 2222","serviceName","ssh"));
        check(NmapScriptPlanner.specializations(List.of(2222),observations).contains("ssh2-enum-algos"));
        check(NmapScriptPlanner.specializations(List.of(135),List.of()).isEmpty());
        check(NmapScriptPlanner.specializations(List.of(445),List.of()).contains("smb2-security-mode"));
        String base=NmapScriptPlanner.select(TestNmapTemplates.load().vulnerabilities.argv,List.of(135),List.of());
        check(base.contains("vuln and safe")&&!base.contains("smb2-security-mode"));
        String smart=NmapScriptPlanner.select(TestNmapTemplates.load().vulnerabilities.argv,List.of(445),List.of());
        check(smart.contains("smb2-security-mode")&&smart.contains("not exploit"));
        System.out.println("NmapScriptPlannerTests passed");
    }
}
