package com.netmap.android;

import java.util.*;
import java.util.regex.*;

/** Safe, protocol-aware NSE selection and failure diagnostics. Never runs brute, exploit or intrusive scripts. */
final class NmapScriptPlanner {
    private NmapScriptPlanner() {}
    private static final Pattern FAILURE=Pattern.compile("(?m)^\\s*[|_ ]*([A-Za-z0-9_-]{1,90}):\\s*ERROR:\\s*Script execution failed\\b");
    static List<String> failures(String stdout,String stderr) {
        LinkedHashSet<String> ids=new LinkedHashSet<>();
        for(String output:Arrays.asList(stdout,stderr)) {
            Matcher matcher=FAILURE.matcher(output==null?"":output);
            while(matcher.find()) ids.add(matcher.group(1));
        }
        return new ArrayList<>(ids);
    }
    static List<String> specializations(Collection<Integer> ports,List<DeviceEvidence.Observation> observations) {
        Set<String> scripts=new LinkedHashSet<>();
        for(Integer port:ports) {
            if(port==null) continue;
            String service="";
            for(DeviceEvidence.Observation item:observations)
                if(item.source.equals("Nmap service "+port)&&item.field.equals("serviceName")) {service=item.value.toLowerCase(Locale.ROOT);break;}
            if(port==445 || service.equals("microsoft-ds")) {
                scripts.add("smb-protocols");
                scripts.add("smb2-security-mode");
            }
            if(port==22 || service.equals("ssh")) scripts.add("ssh2-enum-algos");
            if(port==443 || service.equals("https") || service.equals("ssl/http")) scripts.add("ssl-cert");
        }
        return new ArrayList<>(scripts);
    }
    static String select(List<String> template,Collection<Integer> ports,List<DeviceEvidence.Observation> observations) {
        int index=template.indexOf("--script");
        if(index<0 || index+1>=template.size())throw new IllegalArgumentException("Missing vulnerability NSE selection");
        String base=template.get(index+1);
        List<String> extra=specializations(ports,observations);
        if(extra.isEmpty())return base;
        return "("+base+") or ("+String.join(" or ",extra)+")";
    }
}
