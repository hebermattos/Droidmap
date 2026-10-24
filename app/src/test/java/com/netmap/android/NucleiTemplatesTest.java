package com.netmap.android;

import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class NucleiTemplatesTest {
    @Test public void eachSelectionHasOnlyItsOwnBundledTemplates() throws Exception {
        Set<String> all=new HashSet<>();
        for(int mask=1;mask<=NucleiTemplates.ALL;mask++) {
            assertEquals(Integer.bitCount(mask)*7,NucleiTemplates.files(mask).size());
            assertEquals(NucleiTemplates.files(mask).size(),new HashSet<>(NucleiTemplates.files(mask)).size());
            assertEquals(Integer.bitCount(mask),NucleiTemplates.groups(mask).size());
            for(String name:NucleiTemplates.files(mask)) {
                try(var input=getClass().getClassLoader().getResourceAsStream("nuclei/"+name)) {
                    assertNotNull(name,input);
                    String text=new String(input.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8);
                    assertTrue(text.contains("method: GET"));assertTrue(text.contains("redirects: false"));
                }
                all.add(name);
            }
        }
        assertEquals(21,all.size());
        assertFalse(NucleiTemplates.files(1).contains("droidmap-security-headers.yaml"));
        assertFalse(NucleiTemplates.files(4).contains("droidmap-env-exposure.yaml"));
        assertTrue(NucleiTemplates.files(1).contains("droidmap-npmrc.yaml"));
        assertFalse(NucleiTemplates.files(2).contains("droidmap-npmrc.yaml"));
        assertTrue(NucleiTemplates.files(2).contains("droidmap-cors-credentials.yaml"));
        assertTrue(NucleiTemplates.files(4).contains("droidmap-actuator-env.yaml"));
        assertTrue(NucleiTemplates.summary(7).contains("21 configured templates"));
        for(int mask:new int[]{0,-1,8,15})try {NucleiTemplates.validate(mask);fail("Invalid mask "+mask);}
        catch(IllegalArgumentException expected) { }
    }
    @Test public void informationalMatchesAreNotVulnerabilityAlerts() {
        for(String severity:new String[]{"info","unknown"}) {
            ReportPresentation.Finding finding=new ReportPresentation.Finding("Nuclei","Diagnostic endpoint","port 80",NucleiTemplates.findingEvidence(severity,"Endpoint is visible"));
            assertFalse(finding.alert);assertEquals("Informational result",finding.assessment);
        }
        ReportPresentation.Finding finding=new ReportPresentation.Finding("Nuclei","Git exposure","port 80",NucleiTemplates.findingEvidence("medium","Git metadata is exposed"));
        assertTrue(finding.alert);assertEquals("Alert — review required",finding.assessment);
    }
}
