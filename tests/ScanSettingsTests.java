package com.netmap.android;

import java.util.List;

/** Regression checks for preset scope, saved custom settings and scan startup values. */
public final class ScanSettingsTests {
    private static int assertions;
    private static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    public static void main(String[] args) {
        int[] counts={19,39,65535};
        for(ScanSettings.Preset preset:ScanSettings.Preset.values()) {
            if(preset==ScanSettings.Preset.CUSTOM)continue;
            String ports=preset.selection("invalid draft");
            ScanSettings selected=new ScanSettings(ports,350,preset.depth(false),false,true,"--reason",9);
            check(selected.preset()==preset,"Preset round trip: "+preset);
            ScanPlan plan=new ScanPlan("192.168.0.1",selected.ports,selected.timeoutMs,selected.mode,selected.adaptive);
            check(plan.ports.size()==counts[preset.ordinal()],"Exact scan scope: "+preset);
            check(plan.mode==preset.mode,"Preset depth reaches scanner: "+preset);
            check(selected.summary().equals(preset.label+" • "+counts[preset.ordinal()]+" TCP ports"),"Readable summary");
        }
        ScanSettings quickReordered=new ScanSettings(String.join(",",ScanPlan.parsePorts(ScanPlan.FAST_PORTS).stream()
                .sorted(java.util.Comparator.reverseOrder()).map(String::valueOf).toArray(String[]::new)),
                200,ScanPlan.Mode.FAST,true);
        check(quickReordered.preset()==ScanSettings.Preset.QUICK,"Equivalent saved lists recognized without rewriting preferences");
        for(ScanPlan.Mode mode:ScanPlan.Mode.values()) {
            ScanSettings original=new ScanSettings("22,8000-8002",700,mode,false,false,"--reason",9);
            check(original.preset()==ScanSettings.Preset.CUSTOM,"Custom settings identified");
            ScanSettings restored=new ScanSettings(ScanSettings.Preset.CUSTOM.selection(original.ports),original.timeoutMs,
                    ScanSettings.Preset.CUSTOM.depth(original.mode==ScanPlan.Mode.COMPLETE),original.adaptive,
                    original.nmap,original.nmapArgs,original.nmapVersionIntensity);
            check(restored.ports.equals(original.ports)&&restored.mode==original.mode,"Custom scope and depth preserved");
            check(restored.timeoutMs==700&&!restored.adaptive&&!restored.nmap&&restored.nmapArgs.equals("--reason")
                    &&restored.nmapVersionIntensity==9,"Advanced and tool options preserved");
            check(restored.summary().equals("Custom • 4 TCP ports"),"Custom range count");
        }
        ScanSettings oldAll=new ScanSettings(ScanPlan.ALL_PORTS,500,ScanPlan.Mode.FAST,true);
        check(oldAll.preset()==ScanSettings.Preset.CUSTOM,"Legacy all-ports Fast depth is never silently upgraded");
        check(new ScanSettings(ScanPlan.COMPLETE_PORTS,200,ScanPlan.Mode.FAST,true).preset()==ScanSettings.Preset.CUSTOM,
                "Mixed legacy scope and depth preserved as custom");
        check(ScanPlan.parsePorts(ScanSettings.Preset.CUSTOM.selection(" 443,80,80,8000-8002 "))
                .equals(List.of(80,443,8000,8001,8002)),"Custom ranges still validated and deduplicated");
        for(String invalid:List.of("", "0", "65536", "90-80", "80,")) {
            try {new ScanSettings(ScanSettings.Preset.CUSTOM.selection(invalid),200,ScanPlan.Mode.FAST,true);
                throw new AssertionError("Invalid custom selection accepted");}
            catch(IllegalArgumentException expected){check(true,"Custom validation retained");}
        }
        System.out.println("PASS: "+assertions+" scan preset and custom settings assertions");
    }
}
