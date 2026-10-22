package com.netmap.android;

import java.util.*;

/** Protocol admission from observations, never from a port number alone. */
final class WebEndpoints {
    private WebEndpoints() {}
    static String scheme(List<DeviceEvidence.Observation> observations,int port) {
        String protocol="";
        boolean nmapOpen=false;
        for(DeviceEvidence.Observation item:observations) {
            if((item.source.equals("HTTP tcp/"+port)||item.source.equals("HTTPS tcp/"+port))
                    && (item.field.equals("webUrl")||item.field.equals("server")||item.field.equals("httpTitle")))
                return item.source.startsWith("HTTPS")?"https":"http";
            if(item.source.equals("Nmap") && item.field.equals("openPort") && item.value.equals(port+"/tcp"))nmapOpen=true;
            if(item.source.equals("Nmap service "+port) && item.field.equals("serviceName")) {
                String service=item.value.toLowerCase(Locale.ROOT);
                if(Arrays.asList("https","ssl/http","https-alt").contains(service))protocol="https";
                else if(Arrays.asList("http","http-alt","http-proxy").contains(service))protocol="http";
            }
        }
        return nmapOpen?protocol:"";
    }
    static String url(String scheme,String ip,int port) {
        if(!scheme.equals("http")&&!scheme.equals("https"))throw new IllegalArgumentException("HTTP evidence required");
        if(port<1||port>65535)throw new IllegalArgumentException("Invalid port");
        String address=ScanPlan.isIpv6(ip)?"["+ip.replace("%","%25")+"]":ip;
        return scheme+"://"+address+":"+port+"/";
    }
}
