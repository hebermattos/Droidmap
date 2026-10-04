package com.netmap.android;

import android.app.Activity;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.InputType;
import android.widget.*;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class MainActivity extends Activity {
    private EditText target, ports, timeout;
    private Spinner mode;
    private Button start, stop, export, reanalyze, historyButton;
    private CheckBox adaptive;
    private ScanHistory history;
    private List<String> lastDevices=new ArrayList<>();
    private TextView status, output;
    private ProgressBar progress;
    private TcpScanner scanner;
    private DeviceIdentifier identifier;
    private NsdDiscovery discovery;
    private final ExecutorService background = Executors.newSingleThreadExecutor();
    private volatile boolean destroyed;
    private String report = "";
    private String resultText = "";
    private static final String DEFAULT_PORTS=ScanPlan.FAST_PORTS;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        history=new ScanHistory(new java.io.File(getFilesDir(),"scan-history.json"));
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int)(16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        layout.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(pad + insets.getSystemWindowInsetLeft(), pad + insets.getSystemWindowInsetTop(),
                pad + insets.getSystemWindowInsetRight(), pad + insets.getSystemWindowInsetBottom());
            return insets;
        });
        TextView title = new TextView(this); title.setText("Netmap Lite"); title.setTextSize(26); layout.addView(title);
        TextView hint = new TextView(this);
        hint.setText("Local TCP discovery • no root required\nDevice names, models and services when available."); layout.addView(hint);
        mode=new Spinner(this); mode.setId(R.id.scan_mode);
        mode.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,new String[]{"Fast — selected ports, no retries","Complete — more ports, retry and longer discovery"}));
        layout.addView(mode);
        target = field(layout, "Target IP or private network (/24–/32)", "192.168.0.0/24", R.id.target);
        ports = field(layout, "TCP ports (comma-separated or ranges)", DEFAULT_PORTS, R.id.ports);
        timeout = field(layout, "Connection timeout (100–3000 ms)", "500", R.id.timeout);
        timeout.setInputType(InputType.TYPE_CLASS_NUMBER);
        mode.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            public void onNothingSelected(android.widget.AdapterView<?> parent) { }
            public void onItemSelected(android.widget.AdapterView<?> parent,android.view.View view,int position,long id) {
                String current=ports.getText().toString();
                if(current.equals(ScanPlan.FAST_PORTS) || current.equals(ScanPlan.COMPLETE_PORTS)) ports.setText(position==0?ScanPlan.FAST_PORTS:ScanPlan.COMPLETE_PORTS);
            }
        });
        adaptive=new CheckBox(this); adaptive.setId(R.id.adaptive_scan); adaptive.setText("Adaptive scan (prioritize responders)"); adaptive.setChecked(true); layout.addView(adaptive);
        Button local = new Button(this); local.setText("Use Wi-Fi network"); layout.addView(local);
        local.setOnClickListener(v -> suggestWifi());
        LinearLayout buttons = new LinearLayout(this);
        start = button(buttons, "Start"); stop = button(buttons, "Cancel"); export = button(buttons, "Export JSON");
        layout.addView(buttons); stop.setEnabled(false); export.setEnabled(false);
        LinearLayout extraButtons=new LinearLayout(this);
        reanalyze=button(extraButtons,"Reanalyze IP"); historyButton=button(extraButtons,"History"); layout.addView(extraButtons);
        reanalyze.setEnabled(false); reanalyze.setOnClickListener(v->chooseDevice()); historyButton.setOnClickListener(v->showHistory());
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal); layout.addView(progress);
        status = new TextView(this); status.setText("Ready"); layout.addView(status);
        ScrollView scroll = new ScrollView(this);
        output = new TextView(this); output.setTextIsSelectable(true); output.setTextSize(14); scroll.addView(output);
        layout.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1)); setContentView(layout);
        start.setOnClickListener(v -> begin());
        stop.setOnClickListener(v -> { if (scanner != null) scanner.cancel(); if(identifier!=null) identifier.cancel(); if(discovery!=null) discovery.stop(); stop.setEnabled(false); status.setText("Cancelling…"); });
        export.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE);
            intent.putExtra(Intent.EXTRA_TITLE, "netmap-scan.json"); startActivityForResult(intent, 10);
        });
        if (state != null) {
            report = state.getString("report", ""); resultText = state.getString("results", "");
            output.setText(resultText); export.setEnabled(!report.isEmpty());
            status.setText(state.getBoolean("running") ? "Scan stopped after screen recreation. Start again to rescan." : "Ready");
        }
    }
    private void chooseDevice() {
        if(scanner!=null || lastDevices.isEmpty()) return;
        String[] ips=lastDevices.toArray(new String[0]);
        new android.app.AlertDialog.Builder(this).setTitle("Reanalyze a device")
            .setItems(ips,(dialog,index)-> {target.setText(ips[index]); mode.setSelection(1); ports.setText(ScanPlan.COMPLETE_PORTS); begin();})
            .setNegativeButton("Cancel",null).show();
    }
    private void showHistory() {
        if(scanner!=null) return;
        background.execute(()-> {
            try {
                JSONArray entries=history.load();String[] labels=new String[entries.length()];
                for(int i=0;i<entries.length();i++) {JSONObject entry=entries.getJSONObject(i); labels[i]=new java.text.SimpleDateFormat("MM-dd HH:mm",Locale.US).format(new Date(entry.getLong("time")))+" • "+entry.getString("target");}
                runOnUiThread(()-> {
                    if(destroyed || scanner!=null) return;
                    if(labels.length==0) {new android.app.AlertDialog.Builder(this).setMessage("No completed scans saved yet.").setPositiveButton("OK",null).show();return;}
                    new android.app.AlertDialog.Builder(this).setTitle("Recent scans")
                        .setItems(labels,(dialog,index)-> {try {new android.app.AlertDialog.Builder(this).setTitle("Scan summary").setMessage(ScanHistory.describe(entries.getJSONObject(index))).setPositiveButton("OK",null).show();}catch(Exception ignored){}})
                        .setNegativeButton("Close",null).show();
                });
            } catch(Exception e) {runOnUiThread(()-> {if(!destroyed) status.setText("History unavailable");});}
        });
    }
    private EditText field(LinearLayout layout, String label, String value, int id) {
        TextView caption = new TextView(this); caption.setText(label); layout.addView(caption);
        EditText field = new EditText(this); field.setId(id); field.setSingleLine(true); field.setText(value); layout.addView(field); return field;
    }
    private Button button(LinearLayout layout, String text) {
        Button button = new Button(this); button.setText(text); layout.addView(button, new LinearLayout.LayoutParams(0, -2, 1)); return button;
    }
    private void suggestWifi() {
        ConnectivityManager cm = (ConnectivityManager)getSystemService(CONNECTIVITY_SERVICE);
        for (Network network : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) continue;
            LinkProperties properties = cm.getLinkProperties(network);
            if (properties == null) continue;
            for (LinkAddress address : properties.getLinkAddresses()) {
                if (!(address.getAddress() instanceof Inet4Address)) continue;
                String value = address.getAddress().getHostAddress() + "/" + Math.max(24, address.getPrefixLength());
                try { ScanPlan.parseHosts(value); target.setText(value); return; } catch (IllegalArgumentException ignored) { }
            }
        }
        status.setText("No private Wi-Fi IPv4 network found. Connect to Wi-Fi or enter a target manually.");
    }
    private void begin() {
        final ScanPlan plan;
        final String targetValue = target.getText().toString().trim();
        try { plan = new ScanPlan(targetValue, ports.getText().toString(), Integer.parseInt(timeout.getText().toString().trim()),mode.getSelectedItemPosition()==0?ScanPlan.Mode.FAST:ScanPlan.Mode.COMPLETE,adaptive.isChecked()); }
        catch (IllegalArgumentException e) { status.setText(e.getMessage()); return; }
        scanner = new TcpScanner(); final TcpScanner current = scanner;
        final DeviceEvidence evidence=new DeviceEvidence(plan.hosts);
        final DeviceIdentifier identity=new DeviceIdentifier(plan,evidence); identifier=identity;
        identity.setHostnameLookup(WifiReverseDns.create(this,plan,evidence));
        final NsdDiscovery nsd=new NsdDiscovery(this,evidence,plan.mode); discovery=nsd; nsd.start();
        report = ""; resultText = ""; output.setText(""); export.setEnabled(false);
        start.setEnabled(false); stop.setEnabled(true); reanalyze.setEnabled(false); historyButton.setEnabled(false); adaptive.setEnabled(false);
        target.setEnabled(false); ports.setEnabled(false); timeout.setEnabled(false); mode.setEnabled(false);
        int total = plan.hosts.size() * plan.ports.size(); progress.setMax(total); progress.setProgress(0);
        status.setText("Scanning " + plan.hosts.size() + " addresses…");
        final long started = System.currentTimeMillis();
        AtomicLong lastUpdate = new AtomicLong(); AtomicInteger completed = new AtomicInteger();
        background.execute(() -> {
            try {
                List<TcpScanner.Result> results = current.scan(plan, (result, count, max) -> {
                    completed.accumulateAndGet(count, Math::max);
                    long now = SystemClock.elapsedRealtime(); long previous = lastUpdate.get();
                    if (now - previous >= 150 && lastUpdate.compareAndSet(previous, now)) runOnUiThread(() -> {
                        if (destroyed || scanner != current || current.isCancelled()) return;
                        int done = completed.get(); progress.setProgress(done); status.setText("Checked " + done + " / " + max + " TCP connections");
                    });
                });
                runOnUiThread(() -> { if(!destroyed && !current.isCancelled()) status.setText("Identifying devices: mDNS, DNS PTR, SSDP and service information…"); });
                if(!current.isCancelled()) nsd.awaitCompletion(current::isCancelled);
                if(!current.isCancelled()) identity.identify(results);
                runOnUiThread(() -> {
                    nsd.stop();
                    if(destroyed || scanner!=current) return;
                    Map<String,List<DeviceEvidence.Observation>> identified=evidence.snapshot();
                    for(TcpScanner.Result check:results) if(check.state==TcpScanner.State.OPEN || check.state==TcpScanner.State.CLOSED) identified.computeIfAbsent(check.host,k->new ArrayList<>());
                    List<String> notices=identity.notices(); notices.addAll(nsd.notices());
                    if(identity.isTimedOut()) notices.add("Identification time budget reached; evidence is partial.");
                    final boolean cancelled=current.isCancelled();
                    background.execute(() -> {
                        try {
                            List<TcpScanner.Result> extra=identity.endpointChecks();
                        List<TcpScanner.Result> displayChecks=new ArrayList<>(results);
                        Map<String,Integer> index=new HashMap<>();
                        for(int i=0;i<displayChecks.size();i++) index.put(displayChecks.get(i).host+":"+displayChecks.get(i).port,i);
                        for(TcpScanner.Result check:extra) {
                            String key=check.host+":"+check.port; Integer found=index.get(key);
                            if(found==null) { index.put(key,displayChecks.size()); displayChecks.add(check); }
                            else if(displayChecks.get(found).state==TcpScanner.State.NO_RESPONSE) displayChecks.set(found,check);
                        }
                        String text=describe(displayChecks,plan,cancelled,identified,notices,results.size(),extra.size());
                            String rawJson=json(results,plan,targetValue,cancelled,started,identified,notices,extra);
                            JSONObject parsed=new JSONObject(rawJson);
                            String changes;
                            try { changes=history.save(parsed,plan); } catch(Exception historyError) { changes="History unavailable: "+historyError.getClass().getSimpleName(); }
                            parsed.put("historyComparison",changes);
                            final String json=parsed.toString(2);
                            final String display=text+"\nHistory comparison\n"+changes+"\n";
                            List<String> devices=new ArrayList<>(ScanHistory.inventory(ScanHistory.compact(parsed,plan)).keySet());
                            runOnUiThread(() -> {
                                if(destroyed || scanner!=current) return;
                                lastDevices=devices;
                                report=json; resultText=display; output.setText(display); progress.setProgress(results.size());
                                status.setText(cancelled?"Cancelled — partial results":"Scan completed"); finishScan(); export.setEnabled(true);
                            });
                        } catch(Exception e) { runOnUiThread(() -> { if(!destroyed) { status.setText("Report failed: "+e.getMessage()); finishScan(); } }); }
                    });
                });
            } catch (Exception e) {
                runOnUiThread(() -> { if (!destroyed) { nsd.stop(); identity.cancel(); status.setText("Scan failed: " + e.getMessage()); finishScan(); } });
            }
        });
    }
    private void finishScan() { scanner = null; identifier=null; discovery=null; start.setEnabled(true); stop.setEnabled(false); target.setEnabled(true); ports.setEnabled(true); timeout.setEnabled(true); mode.setEnabled(true); adaptive.setEnabled(true); historyButton.setEnabled(true); reanalyze.setEnabled(!lastDevices.isEmpty()); }
    private String describe(List<TcpScanner.Result> results, ScanPlan plan, boolean cancelled, Map<String,List<DeviceEvidence.Observation>> identified,List<String> notices,int initialCompleted,int extraCount) {
        Map<String, List<Integer>> hosts = new LinkedHashMap<>(); int errors = 0, silent = 0, open = 0;
        for (TcpScanner.Result result : results) {
            if (result.state == TcpScanner.State.OPEN || result.state == TcpScanner.State.CLOSED) hosts.computeIfAbsent(result.host, k -> new ArrayList<>());
            if (result.state == TcpScanner.State.OPEN) { hosts.get(result.host).add(result.port); open++; }
            if (result.state == TcpScanner.State.ERROR) errors++;
            if (result.state == TcpScanner.State.NO_RESPONSE) silent++;
        }
        for(String ip:identified.keySet()) hosts.computeIfAbsent(ip,k->new ArrayList<>());
        StringBuilder text = new StringBuilder();
        for (Map.Entry<String, List<Integer>> host : hosts.entrySet()) {
            text.append(host.getKey()).append("\n");
            List<DeviceEvidence.Observation> info=identified.getOrDefault(host.getKey(),Collections.emptyList());
            String name=DeviceEvidence.first(info,"friendlyName","serviceName","netbiosName","dnsHostname","httpTitle");
            String maker=DeviceEvidence.first(info,"manufacturer"), model=DeviceEvidence.first(info,"modelName","modelHint");
            text.append("  Name (reported): ").append(name.isEmpty()?"Unknown":name).append("\n");
            if(!maker.isEmpty()) text.append("  Manufacturer (reported): ").append(maker).append("\n");
            String mac=DeviceEvidence.first(info,"reportedMac");
            if(!mac.isEmpty()) text.append("  MAC (reported via NetBIOS): ").append(mac).append("\n");
            if(!model.isEmpty()) text.append("  Model (reported): ").append(model).append("\n");
            DeviceProfile profile=new DeviceProfile(info);
            if(!profile.manufacturer.isEmpty() && maker.isEmpty()) text.append("  Manufacturer (suggested): ").append(profile.manufacturer).append("\n");
            text.append("  Identification: ").append(profile.confidence).append("\n");
            for(String reason:profile.reasons) text.append("  Evidence: ").append(reason).append("\n");
            text.append("  Type (probable): ").append(DeviceEvidence.probableType(info)).append("\n");
            for(DeviceEvidence.Observation item:info) text.append("  [").append(item.source).append("] ").append(item.field).append(": ").append(item.value).append("\n");
            if (host.getValue().isEmpty()) text.append("  No selected TCP ports open.\n");
            for (int port : host.getValue()) text.append("  ").append(port).append("/tcp OPEN\n");
            text.append("\n");
        }
        if (hosts.isEmpty()) text.append("No responding devices detected.\n\n");
        for(String notice:notices) text.append("Notice: ").append(notice).append("\n");
        return text.append("Summary\nResponding devices: ").append(hosts.size()).append(" / ").append(plan.hosts.size())
            .append("\nOpen ports: ").append(open).append("\nNo response: ").append(silent).append("\nConnection errors: ").append(errors)
            .append("\nMode: ").append(plan.mode).append("\nAdvertised endpoint checks: ").append(extraCount).append("\nSelected-port checks: ").append(initialCompleted).append(" / ").append(plan.hosts.size() * plan.ports.size())
            .append(cancelled ? "\nPartial scan.\n" : "\n")
            .append("\nNo response can mean filtering, timeout or an offline device. Names and models are self-reported; probable types are inferred from advertised services. An open port does not establish a vulnerability.").toString();
    }
    private String json(List<TcpScanner.Result> results, ScanPlan plan, String target, boolean cancelled, long started, Map<String,List<DeviceEvidence.Observation>> identified,List<String> notices,List<TcpScanner.Result> endpointChecks) throws Exception {
        JSONObject report = new JSONObject(); report.put("schemaVersion", 4); report.put("adaptive",plan.adaptive); report.put("mode",plan.mode.name()); report.put("timeoutRetries",plan.mode.retries); report.put("target", target);
        report.put("startedAtEpochMs", started); report.put("finishedAtEpochMs", System.currentTimeMillis());
        report.put("cancelled", cancelled); report.put("timeoutMs", plan.timeoutMs); report.put("ports", new JSONArray(plan.ports));
        report.put("plannedChecks", plan.hosts.size() * plan.ports.size()); report.put("completedChecks", results.size());
        JSONArray checks = new JSONArray();
        for (TcpScanner.Result result : results) { JSONObject check = new JSONObject(); check.put("ip", result.host); check.put("port", result.port); check.put("protocol", "tcp"); check.put("state", result.state.name()); check.put("attempts",result.attempts); check.put("finalTimeoutMs",result.timeoutMs); checks.put(check); }
        JSONArray extraChecks=new JSONArray();
        for(TcpScanner.Result result:endpointChecks) { JSONObject entry=new JSONObject(); entry.put("ip",result.host); entry.put("port",result.port); entry.put("protocol","tcp"); entry.put("state",result.state.name()); entry.put("attempts",result.attempts); entry.put("finalTimeoutMs",result.timeoutMs); extraChecks.put(entry); }
        report.put("advertisedEndpointChecks",extraChecks);
        report.put("checks", checks); report.put("identificationNotices",new JSONArray(notices));
        JSONArray devices=new JSONArray();
        for(Map.Entry<String,List<DeviceEvidence.Observation>> host:identified.entrySet()) {
            JSONObject device=new JSONObject(); device.put("ip",host.getKey());
            device.put("dnsHostname",DeviceEvidence.first(host.getValue(),"dnsHostname"));
            device.put("reportedName",DeviceEvidence.first(host.getValue(),"friendlyName","serviceName","netbiosName","dnsHostname","httpTitle"));
            device.put("reportedMac",DeviceEvidence.first(host.getValue(),"reportedMac"));
            device.put("reportedManufacturer",DeviceEvidence.first(host.getValue(),"manufacturer"));
            device.put("reportedModel",DeviceEvidence.first(host.getValue(),"modelName","modelHint"));
            device.put("probableType",DeviceEvidence.probableType(host.getValue())); DeviceProfile profile=new DeviceProfile(host.getValue()); device.put("identityConfidence",profile.confidence);
            device.put("suggestedManufacturer",profile.manufacturer); device.put("identificationReasons",new JSONArray(profile.reasons));
            JSONArray observations=new JSONArray();
            for(DeviceEvidence.Observation item:host.getValue()) { JSONObject entry=new JSONObject(); entry.put("source",item.source); entry.put("field",item.field); entry.put("value",item.value); observations.put(entry); }
            device.put("evidence",observations); devices.put(device);
        }
        report.put("devices",devices); return report.toString(2);
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != 10 || result != RESULT_OK || data == null || data.getData() == null) return;
        final android.net.Uri uri = data.getData(); final String snapshot = report;
        background.execute(() -> {
            try (OutputStream stream = getContentResolver().openOutputStream(uri, "wt")) {
                if (stream == null) throw new java.io.IOException("Unable to open destination");
                stream.write(snapshot.getBytes(StandardCharsets.UTF_8));
                runOnUiThread(() -> { if (!destroyed) status.setText("JSON report saved"); });
            } catch (Exception e) { runOnUiThread(() -> { if (!destroyed) status.setText("Export failed: " + e.getMessage()); }); }
        });
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        // Bound Bundle size: large reports must be exported before rotating.
        if (report.length() < 100000) state.putString("report", report);
        if (resultText.length() < 100000) state.putString("results", resultText); state.putBoolean("running", scanner != null);
    }
    @Override protected void onDestroy() {
        destroyed = true; if (scanner != null) scanner.cancel(); if(identifier!=null) identifier.cancel(); if(discovery!=null) discovery.stop(); background.shutdownNow(); super.onDestroy();
    }
}
