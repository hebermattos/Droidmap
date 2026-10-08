package com.netmap.android;

import android.content.Context;
import android.widget.*;

import org.json.*;

import java.util.*;

/** Report presentation and expandable cards; owns no scan or activity lifecycle. */
final class DeviceResultsRenderer {
    private final Context context;
    private final LinearLayout deviceList;
    private final ScrollView resultsScroll;
    private final Set<String> expandedDevices;
    private final java.util.function.Consumer<String> openNmapOutput;
    private List<String> lastDevices = new ArrayList<>();

    DeviceResultsRenderer(
            Context context,
            LinearLayout deviceList,
            ScrollView resultsScroll,
            Set<String> expandedDevices, java.util.function.Consumer<String> openNmapOutput) {
        this.context = context;
        this.deviceList = deviceList;
        this.resultsScroll = resultsScroll;
        this.expandedDevices = expandedDevices;
        this.openNmapOutput = openNmapOutput;
    }

    List<String> render(String report) {
        int scrollPosition = resultsScroll.getScrollY();
        deviceList.removeAllViews();
        lastDevices = new ArrayList<>();
        if (report.isEmpty()) {
            TextView empty = new TextView(context);
            empty.setText(
                    "Discover devices on your local network.\nUse Options to adjust the scan.");
            deviceList.addView(empty);
            return lastDevices;
        }
        try {
            JSONObject data = new JSONObject(report);
            JSONArray devices = data.getJSONArray("devices");
            TextView heading = new TextView(context);
            heading.setText(
                    devices.length()
                            + (data.optBoolean("partial") ? " devices so far • " : " devices • ")
                            + data.optString("target"));
            heading.setTextSize(18);
            deviceList.addView(heading);
            if (devices.length() == 0) {
                TextView empty = new TextView(context);
                empty.setText(
                        "No devices identified. See Full report in Options for scan details.");
                deviceList.addView(empty);
            }
            Map<String, Set<Integer>> portsByIp = new HashMap<>();
            for (String key : new String[] {"checks", "advertisedEndpointChecks"}) {
                JSONArray checks = data.optJSONArray(key);
                if (checks == null) continue;
                for (int j = 0; j < checks.length(); j++) {
                    JSONObject check = checks.getJSONObject(j);
                    if ("OPEN".equals(check.optString("state")))
                        portsByIp
                                .computeIfAbsent(check.getString("ip"), ignored -> new TreeSet<>())
                                .add(check.getInt("port"));
                }
            }
            for (int i = 0; i < devices.length(); i++) {
                JSONObject device = devices.getJSONObject(i);
                String ip = device.getString("ip");
                lastDevices.add(ip);
                Set<Integer> openPorts = new TreeSet<>(portsByIp.getOrDefault(ip, Collections.emptySet()));
                JSONArray observations=device.optJSONArray("evidence");
                if(observations!=null) for(int j=0;j<observations.length();j++) {
                    JSONObject item=observations.optJSONObject(j);
                    if(item==null||!item.optString("source").equals("Nmap")||!item.optString("field").equals("openPort")) continue;
                    String value=item.optString("value");
                    if(value.endsWith("/tcp")) try {
                        int port=Integer.parseInt(value.substring(0,value.length()-4));
                        if(port>=1&&port<=65535) openPorts.add(port);
                    } catch(NumberFormatException ignored) { }
                }
                addDeviceCard(device, openPorts);
            }
            TextView footer = new TextView(context);
            footer.setText(
                    "Tap a device to expand or collapse details.\n"
                        + "Full report and JSON export are in Options.");
            deviceList.addView(footer);
        } catch (Exception e) {
            TextView fallback = new TextView(context);
            fallback.setText("Summary unavailable. Open Full report in Options.");
            deviceList.addView(fallback);
        }
        resultsScroll.post(() -> resultsScroll.scrollTo(0, scrollPosition));
        return lastDevices;
    }

    private int dp(int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }

    private String portList(Set<Integer> ports, int limit) {
        if (ports.isEmpty()) return "None observed";
        StringBuilder value = new StringBuilder();
        int count = 0;
        for (int port : ports) {
            if (count == limit) break;
            if (count++ > 0) value.append(", ");
            value.append(port);
        }
        if (ports.size() > limit) value.append(" (+").append(ports.size() - limit).append(" more)");
        return value.toString();
    }

    private void addDeviceCard(JSONObject device, Set<Integer> openPorts) {
        String ip = device.optString("ip");
        String name = device.optString("reportedName").replaceAll("\\s+", " ").trim();
        if (name.length() > 64) name = name.substring(0, 61) + "…";
        String summary =
                ip
                        + (name.isEmpty() ? "" : " • " + name)
                        + "\nProbable type: "
                        + device.optString("probableType", "Unknown")
                        + "\nOpen TCP ports: "
                        + portList(openPorts, 8);
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        android.graphics.drawable.GradientDrawable shape =
                new android.graphics.drawable.GradientDrawable();
        shape.setColor(android.graphics.Color.rgb(20, 20, 20));
        shape.setCornerRadius(dp(12));
        shape.setStroke(dp(1), android.graphics.Color.rgb(55, 55, 55));
        card.setBackground(shape);
        LinearLayout.LayoutParams margins = new LinearLayout.LayoutParams(-1, -2);
        margins.setMargins(0, dp(10), 0, 0);
        deviceList.addView(card, margins);
        Button toggle = new Button(context);
        toggle.setAllCaps(false);
        toggle.setGravity(android.view.Gravity.START | android.view.Gravity.CENTER_VERTICAL);
        toggle.setTextSize(16);
        toggle.setPadding(dp(16), dp(12), dp(16), dp(12));
        toggle.setMinHeight(dp(64));
        card.addView(toggle, new LinearLayout.LayoutParams(-1, -2));
        LinearLayout details = new LinearLayout(context);
        details.setOrientation(LinearLayout.VERTICAL);
        details.setPadding(dp(16), 0, dp(16), dp(16));
        card.addView(details);
        boolean expanded = expandedDevices.contains(ip);
        if (expanded) populateDeviceDetails(details, device, openPorts);
        details.setVisibility(expanded ? android.view.View.VISIBLE : android.view.View.GONE);
        setExpansionLabel(toggle, summary, ip, expanded);
        toggle.setOnClickListener(
                v -> {
                    boolean show = details.getVisibility() != android.view.View.VISIBLE;
                    if (show && details.getChildCount() == 0)
                        populateDeviceDetails(details, device, openPorts);
                    details.setVisibility(
                            show ? android.view.View.VISIBLE : android.view.View.GONE);
                    if (show) expandedDevices.add(ip);
                    else expandedDevices.remove(ip);
                    setExpansionLabel(toggle, summary, ip, show);
                });
    }

    private void setExpansionLabel(Button toggle, String summary, String ip, boolean expanded) {
        toggle.setText(summary + "\n" + (expanded ? "▾ Hide details" : "▸ Show details"));
        toggle.setContentDescription(
                summary + ". " + (expanded ? "Collapse" : "Expand") + " details for " + ip);
    }

    private void detailSection(LinearLayout parent, String title) {
        TextView heading = new TextView(context);
        heading.setText(title);
        heading.setTextSize(16);
        heading.setTypeface(null, android.graphics.Typeface.BOLD);
        heading.setPadding(0, dp(16), 0, dp(6));
        parent.addView(heading);
    }

    private TextView detailValue(LinearLayout parent, String label, String value) {
        if (value.isEmpty()) return null;
        TextView caption = new TextView(context);
        caption.setText(label);
        caption.setTextSize(12);
        caption.setTextColor(android.graphics.Color.LTGRAY);
        caption.setPadding(0, dp(8), 0, dp(2));
        parent.addView(caption);
        TextView content = new TextView(context);
        content.setText(value);
        content.setTextSize(15);
        content.setTextIsSelectable(true);
        parent.addView(content);
        return content;
    }

    private void nmapValue(LinearLayout parent,String label,String value,String reference) {
        TextView content=detailValue(parent,label,value);
        if(content!=null&&!reference.isEmpty()) {
            content.setContentDescription(label+": "+value+". Tap to view full Nmap output.");
            content.setOnClickListener(view->openNmapOutput.accept(reference));
        }
    }

    private void populateDeviceDetails(
            LinearLayout details, JSONObject device, Set<Integer> openPorts) {
        detailSection(details, "Open TCP ports");
        detailValue(
                details,
                "Observed ports (" + openPorts.size() + ")",
                portList(openPorts, Integer.MAX_VALUE));
        if(ScanPlan.isIpv6(device.optString("ip"))) {
            detailSection(details,"IPv6 network");
            JSONArray metadata=device.optJSONArray("evidence");
            Set<String> shown=new HashSet<>();
            Set<String> fields=new HashSet<>(Arrays.asList("addressType","networkInterface","addressOrigin","prefixLength","neighborState","neighborMac","reachabilityNote","serviceAddresses"));
            if(metadata!=null) for(int i=0;i<metadata.length();i++) {
                JSONObject item=metadata.optJSONObject(i);
                if(item!=null&&fields.contains(item.optString("field"))&&shown.add(item.optString("field")+item.optString("value")))
                    detailValue(details,evidenceLabel(item.optString("field")),item.optString("value"));
            }
        }
        detailSection(details, "MAC addresses");
        JSONArray macs = device.optJSONArray("macAddresses");
        if (macs == null) {
            // Older saved reports retain their sourced evidence but lack macAddresses.
            macs = new JSONArray();
            List<DeviceEvidence.Observation> legacy = new ArrayList<>();
            JSONArray evidence = device.optJSONArray("evidence");
            if (evidence != null) for (int i = 0; i < evidence.length(); i++) {
                JSONObject item = evidence.optJSONObject(i);
                if (item != null) legacy.add(new DeviceEvidence.Observation(
                        item.optString("source"), item.optString("field"), item.optString("value")));
            }
            for (DeviceEvidence.Observation item : MacAddresses.observations(legacy)) {
                try {
                    macs.put(new JSONObject().put("address", item.value).put("source", item.source)
                            .put("kind", MacAddresses.kind(item.value)));
                } catch (org.json.JSONException ignored) { }
            }
        }
        if (macs == null || macs.length() == 0) {
            detailValue(details, "MAC", "Unavailable — not observed or access restricted");
        } else {
            for (int i = 0; i < macs.length(); i++) {
                JSONObject mac = macs.optJSONObject(i);
                if (mac != null) detailValue(details, "Source: " + mac.optString("source"),
                        mac.optString("address") + "\n" + mac.optString("kind"));
            }
        }
        detailSection(details, "Device identity");
        detailValue(details, "IP address", device.optString("ip"));
        String[] keys = {
            "reportedName",
            "reportedManufacturer",
            "reportedModel",
            "reportedMac",
            "dnsHostname",
            "probableType",
            "identityConfidence",
            "suggestedManufacturer",
            "modelConfidence",
            "manufacturerConfidence",
            "typeConfidence",
            "identificationStatus",
            "probeCoverage"
        };
        String[] labels = {
            "Name (reported)",
            "Manufacturer (reported)",
            "Model (reported)",
            "MAC (reported)",
            "DNS hostname (reported)",
            "Probable type",
            "Identity confidence",
            "Suggested manufacturer",
            "Model confidence",
            "Manufacturer confidence",
            "Type confidence",
            "Identification status",
            "Probe coverage"
        };
        for (int i = 0; i < keys.length; i++)
            detailValue(details, labels[i], device.optString(keys[i]));
        JSONArray findings = device.optJSONArray("analysisFindings");
        if (findings != null && findings.length() > 0) {
            detailSection(details, "Analysis findings");
            for (int i = 0; i < findings.length(); i++)
                detailValue(details, "Finding", findings.optString(i));
        }
        JSONArray reasons = device.optJSONArray("identificationReasons");
        if (reasons != null && reasons.length() > 0) {
            detailSection(details, "Identification reasons");
            for (int i = 0; i < reasons.length(); i++)
                detailValue(details, "Reason " + (i + 1), reasons.optString(i));
        }
        Map<String, List<JSONObject>> sources = new LinkedHashMap<>();
        String serviceOutput="",vulnerabilityOutput="";
        List<JSONObject> nmap = new ArrayList<>();
        List<JSONObject> vulnerabilities = new ArrayList<>();
        JSONArray observations = device.optJSONArray("evidence");
        if (observations != null)
            for (int i = 0; i < observations.length(); i++) {
                JSONObject item = observations.optJSONObject(i);
                if (item != null) {
                    String source = item.optString("source", "Unknown source");
                    if(item.optString("field").equals("outputFile")) {
                        if(source.equals("Nmap"))serviceOutput=item.optString("value");
                        else if(source.equals("Nmap vulnerabilities"))vulnerabilityOutput=item.optString("value");
                        continue;
                    }
                    if (source.equals("Nmap vulnerabilities")) vulnerabilities.add(item);
                    else if (source.startsWith("Nmap")) nmap.add(item);
                    else sources.computeIfAbsent(source, ignored -> new ArrayList<>()).add(item);
                }
            }
        detailSection(details, "Nmap");
        if(!serviceOutput.isEmpty())nmapValue(details,"Full output","Tap a Nmap result to view the full command response.",serviceOutput);
        if (nmap.isEmpty()) {
            detailValue(details, "Service detection", "No Nmap results for this device.");
        } else {
            for (JSONObject item : nmap) {
                String source = item.optString("source", "Nmap");
                String label = source.equals("Nmap")
                        ? evidenceLabel(item.optString("field"))
                        : source.replace("Nmap service ", "Port ") + " • " + evidenceLabel(item.optString("field"));
                nmapValue(details, label, item.optString("value"),serviceOutput);
            }
        }
        detailSection(details, "Nmap vulnerabilities");
        if(!vulnerabilityOutput.isEmpty())nmapValue(details,"Full output","Tap a vulnerability result to view the full command response.",vulnerabilityOutput);
        if (vulnerabilities.isEmpty()) detailValue(details, "Safe checks", "No vulnerability findings reported.");
        else for (JSONObject item : vulnerabilities)
            nmapValue(details, evidenceLabel(item.optString("field")), item.optString("value"),vulnerabilityOutput);
        detailValue(details, "Scope", "NSE selects vulnerability scripts by target port and detected service. Host-level results are labeled separately. Brute force, DoS, intrusive and exploit scripts are excluded. Missing findings do not prove absence of vulnerabilities.");
        detailSection(details, "Other evidence by source");
        if (sources.isEmpty())
            detailValue(details, "Evidence", "No identification metadata collected.");
        for (Map.Entry<String, List<JSONObject>> source : sources.entrySet()) {
            detailSection(details, source.getKey());
            for (JSONObject item : source.getValue())
                detailValue(
                        details, evidenceLabel(item.optString("field")), item.optString("value"));
        }
        detailValue(
                details,
                "Interpretation",
                "Names, models and MAC addresses are self-reported. Device type and suggested"
                    + " identity are inferred; open ports do not establish vulnerabilities.");
    }

    private String evidenceLabel(String field) {
        // Keep unknown protocol fields readable without discarding their original name.
        String label = field.replaceAll("([a-z0-9])([A-Z])", "$1 $2").replace('_', ' ');
        return label.isEmpty()
                ? "Observation"
                : Character.toUpperCase(label.charAt(0)) + label.substring(1);
    }
}
