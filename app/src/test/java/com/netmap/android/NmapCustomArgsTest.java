package com.netmap.android;

import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class NmapCustomArgsTest {
    @Test public void acceptsGlobalTuningArguments() {
        assertEquals(Arrays.asList("-n","--reason","-T3","--max-retries","2","--host-timeout","20s","--version-intensity","7"),
                NmapCustomArgs.parse("-n --reason -T3 --max-retries 2 --host-timeout=20s --version-intensity 7"));
    }
    @Test public void rejectsPortTargetOutputAndScriptOverrides() {
        for(String value:Arrays.asList("-p 22","--script vuln","-oX /tmp/x","--datadir /tmp","192.168.0.1"))
            try { NmapCustomArgs.parse(value); fail("Must reject "+value); } catch(IllegalArgumentException expected) {}
    }
    @Test public void settingsPreserveCustomArgumentsAcrossCompleteDefaults() {
        ScanSettings settings=new ScanSettings("80",200,ScanPlan.Mode.FAST,true,true,"-n -T3");
        assertEquals("-n -T3",settings.nmapArgs);
        assertEquals("-n -T3",settings.completeDefaults().nmapArgs);
    }
}
