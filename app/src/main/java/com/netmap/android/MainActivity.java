package com.netmap.android;

import android.app.Activity;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.widget.*;

import java.net.Inet4Address;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private BluetoothPanel bluetoothPanel;
    private EditText target;
    private Button start;
    private Button clearAll;
    private final List<Button> toolButtons = new ArrayList<>();
    private final Map<String, Button> toolRunButtons = new LinkedHashMap<>();
    private boolean cancellingScan;
    private final Map<String, LinearLayout> toolResults = new LinkedHashMap<>();
    private final Map<String, String> toolReports = new HashMap<>();
    private final Map<String, TextView> toolStatuses = new HashMap<>();
    private String activeTool = "discovery";
    private TextView settingsSummary;
    private LinearLayout deviceList;
    private final Set<String> expandedDevices = new HashSet<>();
    private DeviceResultsRenderer resultsRenderer;
    private ScanSettingsStore settingsStore;
    private ScanSettings settings;
    private ReportExporter exporter;
    private List<String> lastDevices = new ArrayList<>();
    private TextView status;
    private ProgressBar progress;
    private boolean scanRunning, startingScan;
    private ScanSnapshot launchPrevious;
    private Intent pendingScan;
    private ScanSnapshot displayedSnapshot;
    private ScanSnapshot ignoredPreviousSnapshot;
    private final android.os.Handler uiHandler =
            new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable refreshScan =
            new Runnable() {
                public void run() {
                    ScanSnapshot snapshot = ScanService.snapshot();
                    if (snapshot != null && snapshot != displayedSnapshot
                            && snapshot != ignoredPreviousSnapshot) applySnapshot(snapshot);
                    if (!scanRunning && !startingScan && bluetoothPanel != null) {
                        updateToolRunButtons(false);
                        clearAll.setEnabled(!bluetoothPanel.busy());
                    }
                    uiHandler.postDelayed(this, 500);
                }
            };
    private final ExecutorService background = Executors.newSingleThreadExecutor();
    private volatile boolean destroyed;
    private String report = "";
    private String resultText = "";

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow()
                .setSoftInputMode(
                        android.view.WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN
                                | android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        settingsStore = new ScanSettingsStore(getPreferences(MODE_PRIVATE));
        settings = settingsStore.load();
        exporter = new ReportExporter(getApplicationContext());
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setFocusableInTouchMode(true);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        layout.setOnApplyWindowInsetsListener(
                (view, insets) -> {
                    view.setPadding(
                            pad + insets.getSystemWindowInsetLeft(),
                            pad + insets.getSystemWindowInsetTop(),
                            pad + insets.getSystemWindowInsetRight(),
                            pad + insets.getSystemWindowInsetBottom());
                    return insets;
                });
        LinearLayout header = new LinearLayout(this);
        header.setGravity(android.view.Gravity.CENTER_VERTICAL);
        TextView title = new TextView(this);
        title.setText("Droidmap v" + BuildConfig.VERSION_NAME);
        title.setTextSize(22);
        header.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        Button options = new Button(this);
        options.setText("Options");
        options.setContentDescription("Open options menu");
        header.addView(options);
        clearAll = new Button(this);
        clearAll.setText("Clear All");
        clearAll.setContentDescription("Clear all saved scans and results");
        clearAll.setOnClickListener(v -> confirmClearAll());
        header.addView(clearAll);
        layout.addView(header);
        options.setOnClickListener(this::showOptions);
        target =
                field(
                        layout,
                        "Target IP or private network (/24–/32)",
                        "192.168.0.0/24",
                        R.id.target);
        settingsSummary = new TextView(this);
        settingsSummary.setTextSize(13);
        settingsSummary.setPadding(0, pad / 2, 0, pad / 2);
        layout.addView(settingsSummary);
        updateSettingsSummary();
        start = new Button(this);
        start.setText("Cancel running scan");
        // Cancel is placed inside the active tool section while running.
        start.setVisibility(android.view.View.GONE);
        start.setOnClickListener(
                v -> {
                    if (scanRunning) {
                        ScanSnapshot snapshot = ScanService.snapshot();
                        if (snapshot != null && snapshot.running)
                            startService(
                                    new Intent(this, ScanService.class)
                                            .setAction(ScanService.CANCEL)
                                            .putExtra("runId", snapshot.runId));
                        start.setEnabled(false);
                        status.setText("Cancelling…");
                    }
                });
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setVisibility(android.view.View.GONE);
        // Progress is placed inside the active tool section while running.
        status = new TextView(this);
        status.setText("Ready");
        status.setPadding(0, pad / 2, 0, pad / 2);
        status.setAccessibilityLiveRegion(android.view.View.ACCESSIBILITY_LIVE_REGION_POLITE);
        // Keep the status object for internal feedback, without a duplicate top label.
        addToolButton(layout, "Discover devices", "Find devices and identify services without Nmap or Nuclei", "discovery");
        addToolButton(layout, "Run Nmap", "Discover open ports and run Nmap analysis", "nmap");
        addToolButton(layout, "Run Nuclei", "Discover HTTP services and run Nuclei checks", "nuclei");
        bluetoothPanel = new BluetoothPanel(this, layout, () -> scanRunning || startingScan, state);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        // Tool result panels own the visible content; retain this off-screen renderer
        // for existing device selection/report plumbing without duplicate results.
        scroll.setVisibility(android.view.View.GONE);
        deviceList = new LinearLayout(this);
        deviceList.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(deviceList);
        layout.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        ScrollView page = new ScrollView(this);
        page.setFillViewport(true);
        page.addView(layout);
        setContentView(page);
        resultsRenderer = new DeviceResultsRenderer(this, deviceList, scroll, expandedDevices, this::showNmapOutput,
                (ip, port) -> runSelectedPort("nmap", ip, port),
                (ip, port) -> runSelectedPort("nuclei", ip, port));
        if (state != null) {
            pendingScan = state.getParcelable("pendingScan");
            exporter.restore(state);
            ArrayList<String> expanded = state.getStringArrayList("expandedDevices");
            if (expanded != null) expandedDevices.addAll(expanded);
        }
        lastDevices = resultsRenderer.render(report);
        // Opening the app starts with a clean result screen and no saved scan baseline.
        // An active foreground scan is preserved across Activity recreation.
        ScanSnapshot live = ScanService.snapshot();
        if (live != null && live.running) {
            applySnapshot(live);
        } else {
            ignoredPreviousSnapshot = live;
            clearPreviousScanFiles();
            status.setText("Ready — run Discovery to start");
        }
    }

    private void confirmClearAll() {
        if (scanRunning || startingScan || (bluetoothPanel != null && bluetoothPanel.busy())) return;
        new android.app.AlertDialog.Builder(this)
                .setTitle("Clear all results?")
                .setMessage("Delete Bluetooth, Discovery, open ports, Nmap and Nuclei results, scan history and saved Nmap output? Scan settings will be kept.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Clear All", (dialog, which) -> clearAllResults())
                .show();
    }

    private void clearAllResults() {
        if (scanRunning || startingScan || (bluetoothPanel != null && bluetoothPanel.busy())) return;
        if (bluetoothPanel != null) bluetoothPanel.clear();
        ignoredPreviousSnapshot = ScanService.snapshot();
        displayedSnapshot = null;
        launchPrevious = null;
        pendingScan = null;
        exporter.clear();
        report = "";
        resultText = "";
        lastDevices.clear();
        expandedDevices.clear();
        deviceList.removeAllViews();
        toolReports.clear();
        for (LinearLayout content : toolResults.values()) {
            content.removeAllViews();
            ((android.view.View) content.getParent()).setVisibility(android.view.View.GONE);

        }
        for (TextView localStatus : toolStatuses.values()) localStatus.setText("Not run");
        progress.setVisibility(android.view.View.GONE);
        start.setVisibility(android.view.View.GONE);
        clearPreviousScanFiles();
        boolean nmapCleared = deleteScanDirectory(new java.io.File(getFilesDir(), "nmap-output"));
        status.setText(nmapCleared ? "All results cleared — run Discovery to start"
                : "Results cleared, but some Nmap output files could not be deleted");
    }

    private boolean deleteScanDirectory(java.io.File path) {
        if (!path.exists()) return true;
        boolean success = true;
        if (path.isDirectory()) {
            java.io.File[] children = path.listFiles();
            if (children == null) return false;
            for (java.io.File child : children) success &= deleteScanDirectory(child);
        }
        return path.delete() && success;
    }

    private void clearPreviousScanFiles() {
        for (String name : new String[] {
                "latest-scan.json", "discovery-scan.json", "scan-history.json"
        }) {
            java.io.File file = new java.io.File(getFilesDir(), name);
            if (file.exists() && !file.delete())
                android.util.Log.w("Droidmap", "Unable to clear old scan data: " + name);
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        uiHandler.post(refreshScan);
        bluetoothPanel.onStart();
    }

    @Override
    protected void onStop() {
        uiHandler.removeCallbacks(refreshScan);
        bluetoothPanel.onStop();
        super.onStop();
    }

    private void updateToolRunButtons(boolean cancellable) {
        for (Map.Entry<String, Button> entry : toolRunButtons.entrySet()) {
            String tool = entry.getKey();
            Button button = entry.getValue();
            boolean active = (scanRunning || startingScan) && tool.equals(activeTool);
            String name = "discovery".equals(tool) ? "Discovery" : "nmap".equals(tool) ? "Nmap" : "Nuclei";
            String runLabel = "discovery".equals(tool) ? "Discover devices" : "Run " + name;
            boolean hasResults = !toolReports.getOrDefault(tool, "").isEmpty();
            LinearLayout content = toolResults.get(tool);
            boolean expanded = content != null
                    && ((android.view.View) content.getParent()).getVisibility() == android.view.View.VISIBLE;
            button.setText(active ? (cancellingScan ? "Stopping " + name + "…" : "Stop " + name)
                    : hasResults ? (expanded ? "− " : "+ ") + name : runLabel);
            button.setEnabled(active ? cancellable && !cancellingScan : !scanRunning && !startingScan && (bluetoothPanel == null || !bluetoothPanel.busy()));
            button.setContentDescription(active ? "Stop running " + name
                    : hasResults ? (expanded ? "Collapse " : "Expand ") + name + " results. Long press to run again"
                    : runLabel);
        }
    }

    private void stopActiveTool() {
        if (!scanRunning || cancellingScan) return;
        ScanSnapshot snapshot = ScanService.snapshot();
        if (snapshot == null || !snapshot.running || !snapshot.cancellable) return;
        cancellingScan = true;
        startService(new Intent(this, ScanService.class)
                .setAction(ScanService.CANCEL).putExtra("runId", snapshot.runId));
        TextView local = toolStatuses.get(activeTool);
        if (local != null) local.setText("Cancelling " + activeTool + "…");
        updateToolRunButtons(false);
    }

    private void moveRunControls(String tool) {
        TextView localStatus = toolStatuses.get(tool);
        if (localStatus == null) return;
        android.view.ViewGroup section = (android.view.ViewGroup) localStatus.getParent();
        android.view.ViewParent parent = progress.getParent();
        if (parent instanceof android.view.ViewGroup)
            ((android.view.ViewGroup) parent).removeView(progress);
        section.addView(progress);
    }

    private void applySnapshot(ScanSnapshot snapshot) {
        if (startingScan && (snapshot == launchPrevious || ScanService.snapshot() == null)) return;
        startingScan = false;
        displayedSnapshot = snapshot;
        scanRunning = snapshot.running;
        moveRunControls(activeTool);
        start.setVisibility(android.view.View.GONE);
        if (!scanRunning) cancellingScan = false;
        updateToolRunButtons(snapshot.cancellable);
        clearAll.setEnabled(!scanRunning && !startingScan);
        start.setEnabled(!scanRunning || snapshot.cancellable);
        target.setEnabled(!scanRunning);
        progress.setVisibility(scanRunning ? android.view.View.VISIBLE : android.view.View.GONE);
        progress.setIndeterminate(scanRunning && (snapshot.total <= 0 || snapshot.done >= snapshot.total));
        if (!progress.isIndeterminate()) {
            progress.setMax(Math.max(1, snapshot.total));
            progress.setProgress(snapshot.done);
        }
        status.setText(snapshot.message);
        TextView localStatus = toolStatuses.get(activeTool);
        if (localStatus != null) localStatus.setText(snapshot.message);
        if (scanRunning) target.setText(snapshot.target);
        if (!report.equals(snapshot.report)) {
            report = snapshot.report;
            resultText = snapshot.text;
            toolReports.put(activeTool, report);
            LinearLayout content = toolResults.get(activeTool);
            if (content != null) {
                content.removeAllViews();
                DeviceResultsRenderer inline = new DeviceResultsRenderer(this, content, new ScrollView(this),
                        expandedDevices, this::showNmapOutput,
                        (ip, port) -> runSelectedPort("nmap", ip, port),
                        (ip, port) -> runSelectedPort("nuclei", ip, port));
                inline.render(report);
                ((android.view.View) content.getParent()).setVisibility(report.isEmpty()
                        ? android.view.View.GONE : android.view.View.VISIBLE);
                updateToolRunButtons(snapshot.cancellable);
            }
            lastDevices = resultsRenderer.render(report);
        } else resultText = snapshot.text;
    }

    private void updateSettingsSummary() {
        settingsSummary.setText(settings.summary());
    }

    private void showSettings() {
        if (scanRunning) return;
        ScanSettingsDialog.show(
                this,
                settings,
                updated -> {
                    settings = updated;
                    settingsStore.save(updated);
                    updateSettingsSummary();
                });
    }

    private void showOptions(android.view.View anchor) {
        OptionsPage.show(this, settings, scanRunning, !lastDevices.isEmpty(),
                !resultText.isEmpty(), !scanRunning && !report.isEmpty(),
                updated -> {
                    settings = updated;
                    settingsStore.save(updated);
                    updateSettingsSummary();
                },
                new OptionsPage.Actions() {
                    @Override public void useWifi(boolean allAddresses) {
                        selectWifiNetwork(allAddresses);
                    }
                    @Override public void openHistory() { showHistory(); }
                    @Override public void reanalyzeDevice() { chooseDevice(); }
                    @Override public void openReport() { showReadableReport(); }
                    @Override public void exportJson() { MainActivity.this.exportJson(); }
                });
    }

    private void showChoiceDialog(String title, String[] labels, boolean[] enabled,
                                  java.util.function.IntConsumer action) {
        String[] display = labels.clone();
        for (int i = 0; i < display.length; i++) {
            if (!enabled[i]) display[i] += " (unavailable)";
        }
        new android.app.AlertDialog.Builder(this)
                .setTitle(title)
                .setItems(display, (dialog, position) -> {
                    if (enabled[position]) action.accept(position);
                })
                .setNegativeButton("Close", null)
                .show();
    }

    private void showTargetOptions() {
        boolean idle = !scanRunning;
        showChoiceDialog("Scan targets",
                new String[] {"Scan a single IP", "Use Wi-Fi network", "Scan all Wi-Fi IPs"},
                new boolean[] {idle, idle, idle},
                position -> {
                    switch (position) {
                        case 0: selectSingleIp(); break;
                        case 1: suggestWifi(); break;
                        case 2: selectAllWifiIps(); break;
                    }
                });
    }

    private void showHistoryOptions() {
        showChoiceDialog("History & reanalysis",
                new String[] {"History", "Reanalyze a device"},
                new boolean[] {!scanRunning, !scanRunning && !lastDevices.isEmpty()},
                position -> {
                    if (position == 0) showHistory();
                    else chooseDevice();
                });
    }

    private void showReportOptions() {
        showChoiceDialog("Reports & export",
                new String[] {"Full report", "Export JSON"},
                new boolean[] {!resultText.isEmpty(), !scanRunning && !report.isEmpty()},
                position -> {
                    if (position == 0) showReadableReport();
                    else exportJson();
                });
    }

    private void exportJson() {
        exporter.capture(report, displayedSnapshot == null ? 0 : displayedSnapshot.runId);
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT)
                .setType("application/json")
                .addCategory(Intent.CATEGORY_OPENABLE);
        intent.putExtra(Intent.EXTRA_TITLE, "droidmap-scan.json");
        startActivityForResult(intent, 10);
    }

    private void showNmapSettings() {
        if (scanRunning) return;
        ScanSettingsDialog.showNmap(this, settings, updated -> {
            settings = updated;
            settingsStore.save(updated);
            updateSettingsSummary();
        });
    }

    private void selectSingleIp() {
        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setHint("192.168.0.1");
        String current = target.getText().toString().trim();
        if (!current.contains("/")) input.setText(current);
        android.app.AlertDialog dialog = new android.app.AlertDialog.Builder(this)
                .setTitle("Scan a single IP")
                .setView(input)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Use IP", null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(view -> {
                    String value = input.getText().toString().trim();
                    try {
                        if (value.contains("/") || ScanPlan.parseHosts(value).size() != 1)
                            throw new IllegalArgumentException("Enter one local IP without a network prefix.");
                        target.setText(value);
                        target.setError(null);
                        dialog.dismiss();
                    } catch (IllegalArgumentException error) {
                        input.setError(error.getMessage());
                    }
                }));
        dialog.show();
    }

    private void showReadableReport() {
        String capturedReport=report,capturedText=resultText;
        background.execute(()->{
            String text;
            try {text=new ReportPresentation(new org.json.JSONObject(capturedReport)).fullText();}
            catch(org.json.JSONException error) {text=capturedText.replace("\\n","\n");}
            String readable=text;
            runOnUiThread(()->{if(!destroyed)showText("Full report",readable);});
        });
    }

    private void showNmapOutput(String reference) {
        background.execute(()->{
            String text;
            try {text=NmapOutputStore.read(getFilesDir(),reference);}
            catch(java.io.IOException error) {text="Cannot open Nmap output: "+error.getMessage();}
            String response=text;
            runOnUiThread(()->{if(!destroyed)showText("Full Nmap output",response,true);});
        });
    }

    private void showText(String title, String text) {
        showText(title,text,false);
    }

    private void showText(String title, String text, boolean technical) {
        ScrollView scroll = new ScrollView(this);
        TextView content = new TextView(this);
        android.text.SpannableString styled=new android.text.SpannableString(text);
        if(!technical) {
            java.util.regex.Matcher headings=java.util.regex.Pattern.compile(
                    "(?m)^(SCAN SUMMARY|DEVICE · .+|Ports and services|Findings|Additional evidence|SCAN NOTICES|HISTORY COMPARISON)$").matcher(text);
            while(headings.find())styled.setSpan(new android.text.style.StyleSpan(android.graphics.Typeface.BOLD),
                    headings.start(),headings.end(),android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        content.setText(styled);
        content.setGravity(android.view.Gravity.START);
        content.setTextAlignment(android.view.View.TEXT_ALIGNMENT_VIEW_START);
        content.setLineSpacing(4*getResources().getDisplayMetrics().density,1f);
        content.setTextIsSelectable(true);
        if(technical) {
            content.setTypeface(android.graphics.Typeface.MONOSPACE);
            content.setTextSize(13);
            content.setHorizontallyScrolling(true);
        }
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        content.setPadding(pad, pad, pad, pad);
        if(technical) {
            HorizontalScrollView horizontal=new HorizontalScrollView(this);
            horizontal.addView(content);
            scroll.addView(horizontal);
        } else scroll.addView(content);
        android.app.AlertDialog dialog=new android.app.AlertDialog.Builder(this)
                .setTitle(title)
                .setView(scroll)
                .setPositiveButton("Close", null)
                .create();
        dialog.show();
        android.view.Window window=dialog.getWindow();
        if(window!=null)window.setLayout(android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                Math.round(getResources().getDisplayMetrics().heightPixels*0.85f));
    }

    private void chooseDevice() {
        if (scanRunning || lastDevices.isEmpty()) return;
        String[] ips = lastDevices.toArray(new String[0]);
        new android.app.AlertDialog.Builder(this)
                .setTitle("Reanalyze a device")
                .setItems(
                        ips,
                        (dialog, index) -> {
                            target.setText(ips[index]);
                            settings = settings.completeDefaults();
                            settingsStore.save(settings);
                            updateSettingsSummary();
                            begin();
                        })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showHistory() {
        if (scanRunning) return;
        ScanHistoryDialog.show(
                this,
                background,
                () -> !destroyed && !scanRunning,
                () -> !destroyed,
                message -> status.setText(message));
    }

    private EditText field(LinearLayout layout, String label, String value, int id) {
        TextView caption = new TextView(this);
        caption.setText(label);
        caption.setLabelFor(id);
        layout.addView(caption);
        EditText field = new EditText(this);
        field.setId(id);
        field.setSingleLine(true);
        field.setText(value);
        layout.addView(field);
        return field;
    }

    private void selectAllWifiIps() {
        selectWifiNetwork(true);
    }

    private void suggestWifi() {
        selectWifiNetwork(false);
    }

    private boolean selectWifiNetwork(boolean allIps) {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (cm == null) {
            status.setText("Wi-Fi network information is unavailable.");
            return false;
        }
        String limitNotice = "";
        for (Network network : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) continue;
            LinkProperties properties = cm.getLinkProperties(network);
            if (properties == null) continue;
            for (LinkAddress address : properties.getLinkAddresses()) {
                if (!(address.getAddress() instanceof Inet4Address)) continue;
                String value =
                        address.getAddress().getHostAddress()
                                + "/"
                                + Math.max(24, address.getPrefixLength());
                try {
                    if (allIps) value = ScanPlan.wifiNetworkTarget(
                            address.getAddress().getHostAddress(), address.getPrefixLength());
                    ScanPlan.parseHosts(value);
                    target.setText(value);
                    target.setError(null);
                    status.setText(allIps
                            ? "All " + ScanPlan.parseHosts(value).size()
                                    + " usable Wi-Fi IPv4 addresses selected. Tap Start scan."
                            : "Wi-Fi range selected. Tap Start scan.");
                    return true;
                } catch (IllegalArgumentException error) {
                    if (allIps && address.getPrefixLength() < 24) limitNotice = error.getMessage();
                }
            }
        }
        status.setText(
                !limitNotice.isEmpty() ? limitNotice : "No private Wi-Fi IPv4 network found. Connect to Wi-Fi or enter a target"
                        + " manually.");
        return false;
    }

    private void addToolButton(LinearLayout layout, String text, String description, String tool) {
        Button button = new Button(this);
        button.setText(text);
        button.setContentDescription(description);
        layout.addView(button);
        LinearLayout section = new LinearLayout(this);
        section.setOrientation(LinearLayout.VERTICAL);
        TextView localStatus = new TextView(this);
        localStatus.setText("Not run");
        section.addView(localStatus);
        toolStatuses.put(tool, localStatus);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        ScrollView inlineScroll = new ScrollView(this);
        inlineScroll.addView(content);
        inlineScroll.setVisibility(android.view.View.GONE);
        section.addView(inlineScroll, new LinearLayout.LayoutParams(-1, (int)(280 * getResources().getDisplayMetrics().density)));
        toolResults.put(tool, content);
        layout.addView(section);
        toolButtons.add(button);
        toolRunButtons.put(tool, button);
        button.setOnClickListener(v -> {
            if (scanRunning || startingScan) {
                if (tool.equals(activeTool)) stopActiveTool();
            } else if (!toolReports.getOrDefault(tool, "").isEmpty()) {
                boolean shown = inlineScroll.getVisibility() == android.view.View.VISIBLE;
                inlineScroll.setVisibility(shown ? android.view.View.GONE : android.view.View.VISIBLE);
                updateToolRunButtons(false);
            } else begin(tool);
        });
        button.setOnLongClickListener(v -> {
            if (scanRunning || startingScan) return false;
            begin(tool);
            return true;
        });
    }

    private void begin() {
        begin("discovery");
    }

    private boolean hasDiscoveryResults() {
        try {
            org.json.JSONObject previous = new org.json.JSONObject(toolReports.getOrDefault("discovery", ""));
            return previous.optBoolean("discoveryReady", false)
                    && !previous.optBoolean("cancelled", true)
                    && previous.optBoolean("tcpScanComplete", false)
                    && target.getText().toString().trim().equals(previous.optString("target"))
                    && previous.optJSONArray("checks") != null;
        } catch (org.json.JSONException error) { return false; }
    }

    private void runSelectedPort(String tool, String ip, int port) {
        if (bluetoothPanel != null && bluetoothPanel.busy()) {
            Toast.makeText(this, "Stop Bluetooth before starting another scan", Toast.LENGTH_SHORT).show();
            return;
        }
        if (scanRunning || startingScan) {
            Toast.makeText(this,"A scan is already running.",Toast.LENGTH_SHORT).show();
            return;
        }
        if (!hasDiscoveryResults()) {
            new android.app.AlertDialog.Builder(this).setTitle("Discovery required")
                    .setMessage("Run Discovery before analyzing a selected port.")
                    .setPositiveButton("OK",null).show();
            return;
        }
        try {
            org.json.JSONObject data=new org.json.JSONObject(toolReports.getOrDefault("discovery", ""));
            boolean found=false;
            for(String field:new String[]{"checks","advertisedEndpointChecks"}) {
                org.json.JSONArray rows=data.optJSONArray(field);
                if(rows==null)continue;
                for(int i=0;i<rows.length();i++) {
                    org.json.JSONObject row=rows.optJSONObject(i);
                    if(row!=null && ip.equals(row.optString("ip"))
                            && port==row.optInt("port")
                            && "OPEN".equals(row.optString("state")))found=true;
                }
            }
            if(!found)throw new IllegalArgumentException("Selected port is not verified open.");
        } catch(Exception error) {
            Toast.makeText(this,"Run Discovery again: "+error.getMessage(),Toast.LENGTH_LONG).show();
            return;
        }
        begin(tool,ip,port);
    }

    private void begin(String tool) {
        if (bluetoothPanel != null && bluetoothPanel.busy()) {
            Toast.makeText(this, "Stop Bluetooth before starting another scan", Toast.LENGTH_SHORT).show();
            return;
        }
        begin(tool,null,0);
    }

    private void begin(String tool, String selectedIp, int selectedPort) {
        if (("nmap".equals(tool) || "nuclei".equals(tool)) && !hasDiscoveryResults()) {
            new android.app.AlertDialog.Builder(this)
                    .setTitle("Discovery required")
                    .setMessage("Run Discover devices first. Tools analyze verified-open TCP ports from that discovery.")
                    .setPositiveButton("Run Discovery", (dialog, which) -> begin("discovery"))
                    .setNegativeButton("Cancel", null).show();
            return;
        }
        boolean portsOnly = false;
        String targetValue = target.getText().toString().trim();
        try {
            new ScanPlan(
                    targetValue,
                    settings.ports,
                    settings.timeoutMs,
                    settings.mode,
                    settings.adaptive);
        } catch (IllegalArgumentException e) {
            target.setError(e.getMessage());
            return;
        }
        Intent request =
                new Intent(this, ScanService.class)
                        .setAction(ScanService.START)
                        .putExtra("target", targetValue)
                        .putExtra("tool", tool)
                        .putExtra("selectedIp", selectedIp)
                        .putExtra("selectedPort", selectedPort)
                        .putExtra("ports", settings.ports)
                        .putExtra("timeout", settings.timeoutMs)
                        .putExtra("complete", settings.mode == ScanPlan.Mode.COMPLETE)
                        .putExtra("adaptive", settings.adaptive)
                        .putExtra("nmap", "nmap".equals(tool))
                        .putExtra("portsOnly", false)
                        .putExtra("nuclei", "nuclei".equals(tool))
                        .putExtra("nmapArgs", "nmap".equals(tool) ? settings.nmapArgs : "")
                        .putExtra("nmapVersionIntensity", settings.nmapVersionIntensity);
        if (android.os.Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                        != android.content.pm.PackageManager.PERMISSION_GRANTED
                && !getPreferences(MODE_PRIVATE).getBoolean("notificationAsked", false)) {
            pendingScan = request;
            requestPermissions(new String[] {android.Manifest.permission.POST_NOTIFICATIONS}, 20);
            return;
        }
        launchScan(request);
    }

    @Override
    public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request, permissions, results);
        if (bluetoothPanel.permissions(request)) return;
        if (request != 20) return;
        getPreferences(MODE_PRIVATE).edit().putBoolean("notificationAsked", true).apply();
        Intent scan = pendingScan;
        pendingScan = null;
        if (scan != null) launchScan(scan);
        if (results.length == 0
                || results[0] != android.content.pm.PackageManager.PERMISSION_GRANTED)
            Toast.makeText(
                            this,
                            "Notifications are off. Scan progress and cancellation remain available"
                                    + " in the app.",
                            Toast.LENGTH_LONG)
                    .show();
    }

    private void launchScan(Intent request) {
        android.view.inputmethod.InputMethodManager keyboard =
                (android.view.inputmethod.InputMethodManager)
                        getSystemService(INPUT_METHOD_SERVICE);
        if (keyboard != null) keyboard.hideSoftInputFromWindow(target.getWindowToken(), 0);
        target.clearFocus();
        try {
            activeTool = request.getStringExtra("tool");
            launchPrevious = ScanService.snapshot();
            ignoredPreviousSnapshot = null;
            displayedSnapshot = launchPrevious;
            startingScan = true;
            startForegroundService(request);
            scanRunning = true;
            expandedDevices.clear();
            report = "";
            resultText = "";
            deviceList.removeAllViews();
            LinearLayout content = toolResults.get(activeTool);
            if (content != null) { content.removeAllViews();
                ((android.view.View) content.getParent()).setVisibility(android.view.View.GONE); }
            toolReports.remove(activeTool);
            lastDevices.clear();
            moveRunControls(activeTool);
            start.setVisibility(android.view.View.GONE);
            progress.setVisibility(android.view.View.VISIBLE);
            progress.setIndeterminate(true);
            start.setEnabled(false);
            cancellingScan = false;
            updateToolRunButtons(false);
            clearAll.setEnabled(false);
            target.setEnabled(false);
            status.setText("Starting scan…");
            TextView local = toolStatuses.get(activeTool);
            if (local != null) local.setText("Starting scan…");
        } catch (RuntimeException e) {
            startingScan = false;
            scanRunning = false;
            start.setVisibility(android.view.View.GONE);
            start.setEnabled(true);
            updateToolRunButtons(false);
            clearAll.setEnabled(true);
            target.setEnabled(true);
            status.setText("Unable to start scan: " + e.getMessage());
            progress.setVisibility(android.view.View.GONE);
            TextView local = toolStatuses.get(activeTool);
            if (local != null) local.setText(status.getText());
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (bluetoothPanel.result(request, result, data)) return;
        if (request != 10) return;
        if (result != RESULT_OK || data == null || data.getData() == null) {
            exporter.clear();
            return;
        }
        final android.net.Uri uri = data.getData();
        final ExportRequest export = exporter.take();
        background.execute(
                () -> {
                    try {
                        exporter.write(uri, export);
                        runOnUiThread(
                                () -> {
                                    if (!destroyed) status.setText("JSON report saved");
                                });
                    } catch (Exception e) {
                        runOnUiThread(
                                () -> {
                                    if (!destroyed)
                                        status.setText("Export failed: " + e.getMessage());
                                });
                    }
                });
    }

    @Override
    protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        bluetoothPanel.save(state);
        state.putStringArrayList("expandedDevices", new ArrayList<>(expandedDevices));
        if (pendingScan != null) state.putParcelable("pendingScan", pendingScan);
        exporter.saveState(state);
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        bluetoothPanel.close();
        uiHandler.removeCallbacks(refreshScan);
        background.shutdown();
        super.onDestroy();
    }
}


