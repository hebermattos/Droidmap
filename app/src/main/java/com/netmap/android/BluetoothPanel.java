package com.netmap.android;

import android.Manifest;
import android.app.*;
import android.bluetooth.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.location.LocationManager;
import android.os.*;
import android.provider.Settings;
import android.view.View;
import android.widget.*;
import org.json.*;
import java.util.*;
import java.util.function.BooleanSupplier;

/** Inline Bluetooth UI; the foreground service owns scanning across Activity recreation. */
final class BluetoothPanel {
    private static final int PERMISSIONS = 41, ENABLE = 42, EXPORT = 43;
    private final Activity activity;
    private final BooleanSupplier networkBusy;
    private final Button main, export;
    private final Spinner duration;
    private final TextView status;
    private final LinearLayout devices;
    private final ScrollView scroll;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Map<String, Card> cards = new LinkedHashMap<>();
    private final Set<String> expanded = new HashSet<>();
    private final Runnable poll = new Runnable() {
        @Override public void run() { refresh(); handler.postDelayed(this, 1000); }
    };
    private long revision = -1;
    private BluetoothScanService.State rendered;
    private boolean pendingStart, pendingInspection;
    private String pendingAddress = "", exportData;
    private final java.util.concurrent.ExecutorService io = java.util.concurrent.Executors.newSingleThreadExecutor();

    BluetoothPanel(Activity activity, LinearLayout parent, BooleanSupplier networkBusy, Bundle saved) {
        this.activity = activity; this.networkBusy = networkBusy;
        if (saved != null) {
            pendingStart = saved.getBoolean("btPending");
            pendingInspection = saved.getBoolean("btInspect");
            pendingAddress = saved.getString("btAddress", "");
            ArrayList<String> values = saved.getStringArrayList("btExpanded");
            if (values != null) expanded.addAll(values);
        } else if (!BluetoothScanService.snapshot().running) BluetoothScanService.clear();
        devices = new LinearLayout(activity); devices.setOrientation(LinearLayout.VERTICAL);
        scroll = new ScrollView(activity); scroll.addView(devices); scroll.setVisibility(View.GONE);
        main = new Button(activity);
        main.setText("Scan Bluetooth"); parent.addView(main);
        main.setOnClickListener(v -> {
            BluetoothScanService.State state = BluetoothScanService.snapshot();
            if (state.running) stop();
            else if (!state.devices.isEmpty()) { scroll.setVisibility(scroll.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE); label(); }
            else request(false, "");
        });
        main.setOnLongClickListener(v -> { if (!BluetoothScanService.snapshot().running) request(false, ""); return true; });
        LinearLayout controls = new LinearLayout(activity);
        duration = new Spinner(activity);
        duration.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_spinner_dropdown_item,
                new String[]{"30 seconds", "60 seconds", "120 seconds"}));
        duration.setSelection(saved == null ? 1 : saved.getInt("btDuration", 1));
        duration.setContentDescription("Bluetooth scan duration");
        controls.addView(duration, new LinearLayout.LayoutParams(0, -2, 1));
        export = new Button(activity); export.setText("Export BT JSON"); controls.addView(export);
        export.setOnClickListener(v -> {
            exportData = BluetoothScanService.exportJson();
            activity.startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                    .setType("application/json").putExtra(Intent.EXTRA_TITLE, "droidmap-bluetooth.json"), EXPORT);
        });
        parent.addView(controls);
        status = new TextView(activity); status.setTextSize(13);
        status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE); parent.addView(status);
        parent.addView(scroll, new LinearLayout.LayoutParams(-1, (int)(260 * activity.getResources().getDisplayMetrics().density)));
        if ((saved != null && saved.getBoolean("btVisible")) || BluetoothScanService.snapshot().running) scroll.setVisibility(View.VISIBLE);
        refresh();
    }
    boolean busy() { return BluetoothScanService.snapshot().running || pendingStart; }
    void onStart() { handler.post(poll); }
    void onStop() { handler.removeCallbacks(poll); }
    void close() { onStop(); io.shutdown(); }
    void save(Bundle out) {
        out.putBoolean("btPending", pendingStart); out.putBoolean("btInspect", pendingInspection);
        out.putString("btAddress", pendingAddress); out.putInt("btDuration", duration.getSelectedItemPosition());
        out.putStringArrayList("btExpanded", new ArrayList<>(expanded)); out.putBoolean("btVisible", scroll.getVisibility() == View.VISIBLE);
    }
    void clear() { BluetoothScanService.clear(); cards.clear(); expanded.clear(); devices.removeAllViews(); scroll.setVisibility(View.GONE); refresh(); }

    private void request(boolean inspect, String address) {
        if (pendingStart || networkBusy.getAsBoolean() || BluetoothScanService.snapshot().running) { toast("Stop the running scan first"); return; }
        pendingStart = true; pendingInspection = inspect; pendingAddress = address;
        List<String> missing = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= 31) {
            missing(missing, Manifest.permission.BLUETOOTH_SCAN); missing(missing, Manifest.permission.BLUETOOTH_CONNECT);
        }
        missing(missing, Manifest.permission.ACCESS_FINE_LOCATION);
        if (Build.VERSION.SDK_INT >= 33 && !activity.getPreferences(Activity.MODE_PRIVATE).getBoolean("notificationAsked", false))
            missing(missing, Manifest.permission.POST_NOTIFICATIONS);
        if (!missing.isEmpty()) {
            new AlertDialog.Builder(activity).setTitle("Bluetooth scan permissions")
                    .setMessage("Allow nearby devices and precise location while using the app. Location permission allows the broadest BLE beacon discovery. No location coordinates are collected.")
                    .setPositiveButton("Continue", (dialog, which) -> {
                        // Android requires fine and coarse location to be requested together.
                        if (missing.contains(Manifest.permission.ACCESS_FINE_LOCATION)) missing.add(Manifest.permission.ACCESS_COARSE_LOCATION);
                        if (missing.contains(Manifest.permission.POST_NOTIFICATIONS))
                            activity.getPreferences(Activity.MODE_PRIVATE).edit().putBoolean("notificationAsked", true).apply();
                        activity.requestPermissions(missing.toArray(new String[0]), PERMISSIONS);
                    }).setNegativeButton("Cancel", (dialog, which) -> pendingStart = false)
                    .setOnCancelListener(dialog -> pendingStart = false).show();
        } else prepare();
    }
    private void missing(List<String> list, String permission) {
        if (activity.checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) list.add(permission);
    }
    boolean permissions(int request) {
        if (request != PERMISSIONS) return false;
        if (!BluetoothScanService.permitted(activity)) {
            pendingStart = false; status.setText("Bluetooth and precise location permissions are required. Enable them in App settings if denied.");
        } else prepare();
        return true;
    }
    @android.annotation.SuppressLint("MissingPermission")
    private void prepare() {
        BluetoothManager manager = activity.getSystemService(BluetoothManager.class);
        BluetoothAdapter adapter = manager == null ? null : manager.getAdapter();
        if (adapter == null) { pendingStart = false; status.setText("Bluetooth is not supported on this device"); return; }
        try {
            if (!adapter.isEnabled()) { activity.startActivityForResult(new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE), ENABLE); return; }
            LocationManager location = activity.getSystemService(LocationManager.class);
            boolean enabled = location != null && (Build.VERSION.SDK_INT >= 28 ? location.isLocationEnabled()
                    : location.isProviderEnabled(LocationManager.GPS_PROVIDER) || location.isProviderEnabled(LocationManager.NETWORK_PROVIDER));
            if (!enabled) {
                pendingStart = false;
                new AlertDialog.Builder(activity).setTitle("Enable location services")
                        .setMessage("Location services may be required for unfiltered Bluetooth discovery. Enable location, then start the scan again.")
                        .setPositiveButton("Settings", (d, w) -> activity.startActivity(new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS)))
                        .setNegativeButton("Cancel", null).show(); return;
            }
            pendingStart = false;
            if (networkBusy.getAsBoolean() || BluetoothScanService.snapshot().running) { toast("Stop the running scan first"); return; }
            Intent intent = new Intent(activity, BluetoothScanService.class)
                    .setAction(pendingInspection ? BluetoothScanService.INSPECT : BluetoothScanService.START)
                    .putExtra("address", pendingAddress).putExtra("seconds", new int[]{30,60,120}[duration.getSelectedItemPosition()]);
            if (!pendingInspection) { cards.clear(); expanded.clear(); devices.removeAllViews(); }
            scroll.setVisibility(View.VISIBLE);
            activity.startForegroundService(intent);
            status.setText("Starting Bluetooth…");
            handler.postDelayed(this::refresh, 250);
        } catch (RuntimeException e) { pendingStart = false; status.setText("Unable to start Bluetooth: " + e.getMessage()); }
    }
    boolean result(int request, int result, Intent data) {
        if (request == ENABLE) { if (result == Activity.RESULT_OK && pendingStart) prepare(); else { pendingStart = false; status.setText("Bluetooth was not enabled"); } return true; }
        if (request != EXPORT) return false;
        String json = exportData; exportData = null;
        if (result == Activity.RESULT_OK && data != null && data.getData() != null) {
            // Recreate a snapshot after Activity recreation, when the original selection is no longer retained.
            if (json == null) json = BluetoothScanService.exportJson();
            final String content = json;
            android.net.Uri uri = data.getData();
            io.execute(() -> {
                try (java.io.OutputStream out = activity.getContentResolver().openOutputStream(uri, "wt")) {
                    if (out == null) throw new java.io.IOException("Cannot open document");
                    out.write(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    activity.runOnUiThread(() -> toast("Bluetooth JSON saved"));
                } catch (Exception e) { activity.runOnUiThread(() -> toast("Bluetooth export failed: " + e.getMessage())); }
            });
        }
        return true;
    }
    private void stop() {
        BluetoothScanService.State state = BluetoothScanService.snapshot();
        activity.startService(new Intent(activity, BluetoothScanService.class).setAction(BluetoothScanService.STOP).putExtra("runId", state.runId));
    }
    private void label() {
        BluetoothScanService.State state = BluetoothScanService.snapshot();
        main.setText(state.running ? "Stop Bluetooth" : state.devices.isEmpty() ? "Scan Bluetooth" : (scroll.getVisibility() == View.VISIBLE ? "− " : "+ ") + "Bluetooth");
        main.setContentDescription(state.running ? "Stop Bluetooth scan or inspection" : "Scan Bluetooth, or expand results. Long press to scan again");
        main.setEnabled(state.running || !networkBusy.getAsBoolean());
        duration.setEnabled(!state.running); export.setEnabled(!state.devices.isEmpty());
    }
    private void refresh() {
        BluetoothScanService.State state = BluetoothScanService.snapshot(); label();
        if (rendered == state && revision == state.revision) return;
        if (rendered != state) { cards.clear(); devices.removeAllViews(); }
        rendered = state; revision = state.revision;
        status.setText((state.message.equals("Not run") ? "BLE + Classic • No Wi-Fi Discovery required" : state.message) + " • " + state.devices.size() + " devices"
                + (state.omitted > 0 ? " • Capacity reached (512); " + state.omitted + " observations omitted" : "")
                + (Build.VERSION.SDK_INT >= 33 && activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                && state.running ? " • Notifications disabled; use Stop here" : ""));
        for (Map.Entry<String, JSONObject> entry : state.devices.entrySet()) {
            Card card = cards.get(entry.getKey());
            if (card == null) { card = new Card(entry.getKey()); cards.put(entry.getKey(), card); }
            card.update(entry.getValue(), state.running);
        }
    }
    private final class Card {
        final String address;
        final TextView heading, details;
        final Button inspect;
        final LinearLayout body;
        Card(String address) {
            this.address = address;
            LinearLayout box = new LinearLayout(activity); box.setOrientation(LinearLayout.VERTICAL);
            heading = new TextView(activity); heading.setTextSize(15); heading.setPadding(4, 12, 4, 12); box.addView(heading);
            body = new LinearLayout(activity); body.setOrientation(LinearLayout.VERTICAL); body.setBackgroundColor(0xff282828);
            inspect = new Button(activity); inspect.setText("Inspect services (GATT / SDP)"); body.addView(inspect);
            inspect.setOnClickListener(v -> request(true, address));
            details = new TextView(activity); details.setTextIsSelectable(true); details.setTextSize(12); details.setPadding(8, 8, 8, 8); body.addView(details);
            box.addView(body); devices.addView(box);
            heading.setOnClickListener(v -> { if (!expanded.remove(address)) expanded.add(address); update(BluetoothScanService.snapshot().devices.get(address), BluetoothScanService.snapshot().running); });
        }
        void update(JSONObject row, boolean running) {
            if (row == null) return;
            boolean open = expanded.contains(address);
            heading.setText((open ? "− " : "+ ") + row.optString("name", "Unnamed device") + "\n" + address
                    + " • " + row.optString("type") + (row.has("rssi") ? " • " + row.optInt("rssi") + " dBm" : " • Not seen nearby")
                    + " • " + row.optString("bond"));
            heading.setContentDescription((open ? "Collapse " : "Expand ") + row.optString("name", address));
            body.setVisibility(open ? View.VISIBLE : View.GONE);
            inspect.setEnabled(!running && !networkBusy.getAsBoolean());
            if (open) details.setText(format(row));
        }
    }
    private static String format(JSONObject row) {
        StringBuilder text = new StringBuilder();
        text.append("Sources: ").append(row.optJSONArray("sources")).append('\n');
        for (String key : new String[]{"beacon", "observations", "firstSeen", "lastSeen", "rssi", "minRssi", "maxRssi", "deviceClass", "majorClass", "connectable",
                "legacyAdvertisement", "primaryPhy", "secondaryPhy", "advertisingSid", "periodicInterval", "dataStatus", "flags", "txPower", "advertisedTxPower", "inspectionStatus", "sdpStatus", "gattStatus", "gattTruncated"}) {
            if (!row.has(key)) continue;
            Object value = row.opt(key);
            if (key.endsWith("Seen")) value = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date(row.optLong(key)));
            text.append(key.replaceAll("([a-z])([A-Z])", "$1 $2")).append(": ").append(value).append('\n');
        }
        for (String key : new String[]{"advertisedServices", "solicitedServices", "cachedUuids", "sdpUuids"}) {
            JSONArray values = row.optJSONArray(key); if (values == null || values.length() == 0) continue;
            text.append('\n').append(key).append(':').append('\n');
            for (int i = 0; i < values.length(); i++) text.append(values.optString(i)).append(' ').append(BluetoothAdvertisement.uuidName(values.optString(i))).append('\n');
        }
        JSONObject manufacturers = row.optJSONObject("manufacturerData");
        if (manufacturers != null) {
            text.append("\nManufacturer advertisements:\n");
            for (Iterator<String> keys = manufacturers.keys(); keys.hasNext();) {
                String id = keys.next(); JSONObject value = manufacturers.optJSONObject(id);
                text.append(id).append(" • ").append(value.optString("company")).append("\n  ").append(value.optString("hex")).append('\n');
            }
        }
        JSONObject data = row.optJSONObject("serviceData");
        if (data != null) {
            text.append("\nService data:\n");
            for (Iterator<String> keys = data.keys(); keys.hasNext();) {
                String uuid = keys.next(); text.append(uuid).append("\n  ").append(data.optString(uuid)).append('\n');
            }
        }
        JSONArray services = row.optJSONArray("gattServices");
        if (services != null) {
            text.append("\nGATT services:\n");
            for (int i = 0; i < services.length(); i++) {
                JSONObject service = services.optJSONObject(i);
                text.append(service.optString("name")).append(" ").append(service.optString("uuid")).append('\n');
                JSONArray chars = service.optJSONArray("characteristics");
                for (int j = 0; chars != null && j < chars.length(); j++) {
                    JSONObject c = chars.optJSONObject(j);
                    text.append("  ").append(c.optString("name")).append(" ").append(c.optString("uuid")).append('\n');
                    text.append("    ").append(properties(c.optInt("properties"))).append('\n');
                    if (c.has("value")) text.append("    Value: ").append(c.optString("value")).append('\n');
                    if (c.has("readStatus")) text.append("    Read status: ").append(c.opt("readStatus")).append('\n');
                    JSONArray descriptors = c.optJSONArray("descriptors");
                    for (int k = 0; descriptors != null && k < descriptors.length(); k++) text.append("    Descriptor: ").append(descriptors.optString(k)).append('\n');
                }
            }
        }
        if (row.has("lastRawAdvertisement")) text.append("\nLatest raw advertisement:\n").append(row.optString("lastRawAdvertisement")).append('\n');
        if (row.optBoolean("truncatedAdvertisement")) text.append("Incomplete/malformed AD structure; raw bytes retained.\n");
        JSONArray fields = row.optJSONArray("adStructures");
        for (int i = 0; fields != null && i < fields.length(); i++) {
            JSONObject field = fields.optJSONObject(i);
            text.append(String.format(Locale.ROOT, "AD 0x%02X: ", field.optInt("type"))).append(field.optString("hex")).append('\n');
        }
        text.append("\nCompany IDs identify advertisement owners; they do not confirm the hardware maker. Addresses may rotate. Paired-only entries are cached, not proof of proximity.");
        return text.toString();
    }
    private static String properties(int flags) {
        String[] labels = {"Broadcast", "Read", "Write without response", "Write", "Notify", "Indicate", "Signed write", "Extended"};
        List<String> values = new ArrayList<>();
        for (int i = 0; i < labels.length; i++) if ((flags & (1 << i)) != 0) values.add(labels[i]);
        return String.join(", ", values);
    }
    private void toast(String text) { Toast.makeText(activity, text, Toast.LENGTH_LONG).show(); }
}
