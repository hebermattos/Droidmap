package com.netmap.android;

import java.util.*;

/** Findings require protocol evidence; they never assert CVEs from open ports. */
final class AnalysisFindings {
    static List<String> describe(List<DeviceEvidence.Observation> observations) {
        Set<String> findings=new LinkedHashSet<>();
        for(DeviceEvidence.Observation item:observations) {
            if(item.field.equals("tlsValidation")) findings.add("Observed: validated TLS service. No vulnerability assessment performed.");
            if(item.field.equals("probeStatus") && item.source.startsWith("TLS") && item.value.startsWith("TLS validation")) findings.add("Review: TLS handshake or identity validation failed. This does not establish a vulnerability.");
            if(item.field.equals("serviceType") && item.source.startsWith("RTSP")) findings.add("Observed: RTSP media service. OPTIONS did not start a stream or test authentication.");
            if(item.field.equals("smbNegotiatedDialect")) findings.add("Observed: SMB dialect "+item.value+" negotiated. No login, share access or vulnerability assessment performed.");
            if(item.field.equals("banner") && item.value.startsWith("SSH-")) findings.add("Observed: SSH service banner. Version text alone does not confirm a vulnerability.");
            if(item.field.equals("server") && (item.source.startsWith("HTTP ") || item.source.startsWith("HTTPS "))) findings.add("Observed: web service metadata. Authentication and vulnerabilities were not tested.");
        }
        return new ArrayList<>(findings);
    }
}
