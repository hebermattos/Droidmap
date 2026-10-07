package com.netmap.android;

import java.util.*;
import org.json.*;

/** Parses the packaged JSON once for each Nmap enrichment run; malformed files fail explicitly. */
final class NmapCommandsJson {
    static final String ASSET = "nmap-command-templates.json";
    static NmapCommands parse(String text) throws JSONException {
        if (text == null || text.length() > 65536) throw new IllegalArgumentException("Nmap template is too large");
        JSONObject root = new JSONObject(text);
        if (root.getInt("schemaVersion") != 1) throw new IllegalArgumentException("Unsupported Nmap template schema");
        JSONObject execution = root.getJSONObject("execution");
        if (execution.getBoolean("shell")) throw new IllegalArgumentException("Nmap templates must use argv without a shell");
        Map<String, String> environment = new LinkedHashMap<>();
        JSONObject env = execution.getJSONObject("environment");
        Iterator<String> keys = env.keys();
        while (keys.hasNext()) { String key = keys.next(); environment.put(key, env.getString(key)); }
        List<String> ipv6 = Collections.emptyList(), iface = Collections.emptyList();
        JSONArray groups = execution.getJSONArray("conditionalArgumentGroups");
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < groups.length(); i++) {
            JSONObject group = groups.getJSONObject(i); String condition = group.getString("when");
            if (!seen.add(condition)) throw new IllegalArgumentException("Duplicate Nmap condition");
            if (condition.equals("Target is IPv6")) ipv6 = strings(group.getJSONArray("argv"));
            else if (condition.equals("IPv6 target has an explicit interface zone")) iface = strings(group.getJSONArray("argv"));
            else throw new IllegalArgumentException("Unknown Nmap condition: " + condition);
        }
        if (seen.size() != 2) throw new IllegalArgumentException("Missing IPv6 argument groups");
        JSONObject profiles = root.getJSONObject("profiles"), selection = root.getJSONObject("selection");
        JSONObject timeout = root.getJSONObject("variables").getJSONObject("timeoutMs");
        return new NmapCommands(profile(profiles.getJSONObject("serviceDetection")),
                profile(profiles.getJSONObject("vulnerabilityDetection")), ipv6, iface, environment,
                execution.getInt("maximumOutputBytes"), execution.getInt("outputReadTimeoutSeconds"),
                selection.getJSONObject("fast").getInt("maximumAttemptedDevices"),
                selection.getJSONObject("complete").getInt("maximumAttemptedDevices"),
                timeout.getInt("minimum"), timeout.getInt("maximum"));
    }
    private static NmapCommands.Profile profile(JSONObject profile) throws JSONException {
        List<String> args = strings(profile.getJSONArray("argv"));
        if (args.isEmpty()) throw new IllegalArgumentException("Missing Nmap profile arguments");
        return new NmapCommands.Profile(args, profile.getInt("processTimeoutSeconds"));
    }
    private static List<String> strings(JSONArray array) throws JSONException {
        List<String> values = new ArrayList<>();
        for (int i = 0; i < array.length(); i++) values.add(array.getString(i));
        return values;
    }
}
