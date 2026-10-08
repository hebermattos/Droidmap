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
    private EditText target;
    private Button start;
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
    private final android.os.Handler uiHandler =
            new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable refreshScan =
            new Runnable() {
                public void run() {
                    ScanSnapshot snapshot = ScanService.snapshot();
                    if (snapshot != null && snapshot != displayedSnapshot) applySnapshot(snapshot);
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
        start.setText("Start scan");
        layout.addView(start);
        start.setOnClickListener(
                v -> {
                    if (!scanRunning) begin();
                    else {
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
        layout.addView(progress);
        status = new TextView(this);
        status.setText("Ready");
        status.setPadding(0, pad / 2, 0, pad / 2);
        status.setAccessibilityLiveRegion(android.view.View.ACCESSIBILITY_LIVE_REGION_POLITE);
        layout.addView(status);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        deviceList = new LinearLayout(this);
        deviceList.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(deviceList);
        layout.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(layout);
        resultsRenderer = new DeviceResultsRenderer(this, deviceList, scroll, expandedDevices, this::showNmapOutput);
        if (state != null) {
            pendingScan = state.getParcelable("pendingScan");
            exporter.restore(state);
            ArrayList<String> expanded = state.getStringArrayList("expandedDevices");
            if (expanded != null) expandedDevices.addAll(expanded);
        }
        lastDevices = resultsRenderer.render(report);
        background.execute(
                () -> {
                    try {
                        ScanSnapshot saved =
                                new LatestScanStore(
                                                new java.io.File(getFilesDir(), "latest-scan.json"))
                                        .load();
                        runOnUiThread(
                                () -> {
                                    if (destroyed) return;
                                    ScanSnapshot live = ScanService.snapshot();
                                    applySnapshot(live == null ? saved : live);
                                });
                    } catch (Exception e) {
                        runOnUiThread(
                                () -> {
                                    if (!destroyed && ScanService.snapshot() == null)
                                        status.setText("Saved result unavailable");
                                });
                    }
                });
    }

    @Override
    protected void onStart() {
        super.onStart();
        uiHandler.post(refreshScan);
    }

    @Override
    protected void onStop() {
        uiHandler.removeCallbacks(refreshScan);
        super.onStop();
    }

    private void applySnapshot(ScanSnapshot snapshot) {
        if (startingScan && (snapshot == launchPrevious || ScanService.snapshot() == null)) return;
        startingScan = false;
        displayedSnapshot = snapshot;
        scanRunning = snapshot.running;
        start.setText(scanRunning ? "Cancel scan" : "Start scan");
        start.setEnabled(!scanRunning || snapshot.cancellable);
        target.setEnabled(!scanRunning);
        progress.setVisibility(scanRunning ? android.view.View.VISIBLE : android.view.View.GONE);
        progress.setMax(snapshot.total);
        progress.setProgress(snapshot.done);
        status.setText(snapshot.message);
        if (scanRunning) target.setText(snapshot.target);
        if (!report.equals(snapshot.report)) {
            report = snapshot.report;
            resultText = snapshot.text;
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
        PopupMenu menu = new PopupMenu(this, anchor);
        boolean idle = !scanRunning;
        menu.getMenu().add(0, 1, 0, "Scan settings").setEnabled(idle);
        menu.getMenu().add(0, 2, 1, "Use Wi-Fi network").setEnabled(idle);
        menu.getMenu().add(0, 7, 2, "Scan all Wi-Fi IPs").setEnabled(idle);
        menu.getMenu().add(0, 3, 2, "History").setEnabled(idle);
        menu.getMenu()
                .add(0, 4, 3, "Reanalyze a device")
                .setEnabled(idle && !lastDevices.isEmpty());
        menu.getMenu().add(0, 5, 4, "Full report").setEnabled(!resultText.isEmpty());
        menu.getMenu().add(0, 6, 5, "Export JSON").setEnabled(idle && !report.isEmpty());
        menu.setOnMenuItemClickListener(
                item -> {
                    switch (item.getItemId()) {
                        case 1:
                            showSettings();
                            break;
                        case 2:
                            suggestWifi();
                            break;
                        case 3:
                            showHistory();
                            break;
                        case 7:
                            selectAllWifiIps();
                            break;
                        case 4:
                            chooseDevice();
                            break;
                        case 5:
                            showReadableReport();
                            break;
                        case 6:
                            exporter.capture(
                                    report,
                                    displayedSnapshot == null ? 0 : displayedSnapshot.runId);
                            Intent intent =
                                    new Intent(Intent.ACTION_CREATE_DOCUMENT)
                                            .setType("application/json")
                                            .addCategory(Intent.CATEGORY_OPENABLE);
                            intent.putExtra(Intent.EXTRA_TITLE, "droidmap-scan.json");
                            startActivityForResult(intent, 10);
                            break;
                        default:
                            return false;
                    }
                    return true;
                });
        menu.show();
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
            runOnUiThread(()->{if(!destroyed)showText("Full Nmap output",response);});
        });
    }

    private void showText(String title, String text) {
        ScrollView scroll = new ScrollView(this);
        TextView content = new TextView(this);
        content.setText(text);
        content.setTextIsSelectable(true);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        content.setPadding(pad, pad, pad, pad);
        scroll.addView(content);
        new android.app.AlertDialog.Builder(this)
                .setTitle(title)
                .setView(scroll)
                .setPositiveButton("Close", null)
                .show();
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

    private void selectWifiNetwork(boolean allIps) {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (cm == null) {
            status.setText("Wi-Fi network information is unavailable.");
            return;
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
                    return;
                } catch (IllegalArgumentException error) {
                    if (allIps && address.getPrefixLength() < 24) limitNotice = error.getMessage();
                }
            }
        }
        status.setText(
                !limitNotice.isEmpty() ? limitNotice : "No private Wi-Fi IPv4 network found. Connect to Wi-Fi or enter a target"
                        + " manually.");
    }

    private void begin() {
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
                        .putExtra("ports", settings.ports)
                        .putExtra("timeout", settings.timeoutMs)
                        .putExtra("complete", settings.mode == ScanPlan.Mode.COMPLETE)
                        .putExtra("adaptive", settings.adaptive)
                        .putExtra("nmap", settings.nmap);
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
            launchPrevious = ScanService.snapshot();
            displayedSnapshot = launchPrevious;
            startingScan = true;
            startForegroundService(request);
            scanRunning = true;
            expandedDevices.clear();
            report = "";
            resultText = "";
            deviceList.removeAllViews();
            lastDevices.clear();
            start.setText("Cancel scan");
            start.setEnabled(false);
            target.setEnabled(false);
            status.setText("Starting scan…");
        } catch (RuntimeException e) {
            startingScan = false;
            scanRunning = false;
            start.setText("Start scan");
            start.setEnabled(true);
            target.setEnabled(true);
            status.setText("Unable to start scan: " + e.getMessage());
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
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
        state.putStringArrayList("expandedDevices", new ArrayList<>(expandedDevices));
        if (pendingScan != null) state.putParcelable("pendingScan", pendingScan);
        exporter.saveState(state);
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        uiHandler.removeCallbacks(refreshScan);
        background.shutdown();
        super.onDestroy();
    }
}
