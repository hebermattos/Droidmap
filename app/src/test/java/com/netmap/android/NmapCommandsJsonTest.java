package com.netmap.android;

import static org.junit.Assert.*;
import org.junit.Test;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class NmapCommandsJsonTest {
    private String asset() throws IOException {
        try(InputStream input=getClass().getClassLoader().getResourceAsStream(NmapCommandsJson.ASSET)) {
            assertNotNull(input);
            return new String(input.readAllBytes(),StandardCharsets.UTF_8);
        }
    }
    @Test public void packagedJsonControlsArgumentsAndBudgets() throws Exception {
        JSONObject root=new JSONObject(asset());
        NmapCommands original=NmapCommandsJson.parse(root.toString());
        assertEquals(4,original.fastLimit); assertEquals(8,original.completeLimit);
        JSONObject profile=root.getJSONObject("profiles").getJSONObject("serviceDetection");
        profile.put("argv",new JSONArray(List.of("--version-all","-p","{ports}","{host}")));
        profile.put("processTimeoutSeconds",42);
        root.getJSONObject("selection").getJSONObject("fast").put("maximumAttemptedDevices",12);
        NmapCommands changed=NmapCommandsJson.parse(root.toString());
        assertEquals(12,changed.fastLimit); assertEquals(42,changed.services.processTimeoutSeconds);
        List<String> command=changed.command(changed.services,"192.168.0.1",changed.bindings("nmap","data","192.168.0.1",List.of(80),200));
        assertTrue(command.contains("--version-all")); assertFalse(command.contains("--version-light"));
    }
    @Test public void invalidTemplatesFailWithoutFallback() throws Exception {
        assertThrows(JSONException.class,()->NmapCommandsJson.parse("{"));
        JSONObject root=new JSONObject(asset()); root.put("schemaVersion",2);
        assertThrows(IllegalArgumentException.class,()->NmapCommandsJson.parse(root.toString()));
        root.put("schemaVersion",1); root.getJSONObject("execution").put("shell",true);
        assertThrows(IllegalArgumentException.class,()->NmapCommandsJson.parse(root.toString()));
        root.getJSONObject("execution").put("shell",false);
        root.getJSONObject("profiles").getJSONObject("serviceDetection").put("argv",new JSONArray(List.of("{unknown}")));
        assertThrows(IllegalArgumentException.class,()->NmapCommandsJson.parse(root.toString()));
    }
}
