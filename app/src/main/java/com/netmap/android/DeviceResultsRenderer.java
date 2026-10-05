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
    private List<String> lastDevices = new ArrayList<>();

    DeviceResultsRenderer(
            Context context,
            LinearLayout deviceList,
            ScrollView resultsScroll,
            Set<String> expandedDevices) {
        this.context = context;
        this.deviceList = deviceList;
        this.resultsScroll = resultsScroll;
        this.expandedDevices = expandedDevices;
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
                Set<Integer> openPorts = portsByIp.getOrDefault(ip, Collections.emptySet());
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

    private void detailValue(LinearLayout parent, String label, String value) {
        if (value.isEmpty()) return;
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
    }

    private void populateDeviceDetails(
            LinearLayout details, JSONObject device, Set<Integer> openPorts) {
        detailSection(details, "Open TCP ports");
        detailValue(
                details,
                "Observed ports (" + openPorts.size() + ")",
                portList(openPorts, Integer.MAX_VALUE));
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
        JSONArray observations = device.optJSONArray("evidence");
        if (observations != null)
            for (int i = 0; i < observations.length(); i++) {
                JSONObject item = observations.optJSONObject(i);
                if (item != null)
                    sources.computeIfAbsent(
                                    item.optString("source", "Unknown source"),
                                    ignored -> new ArrayList<>())
                            .add(item);
            }
        detailSection(details, "Evidence by source");
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
