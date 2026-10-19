package com.netmap.android;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.*;
import android.bluetooth.*;
import android.bluetooth.le.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.os.*;
import org.json.*;
import java.util.*;

/** User-started foreground Bluetooth discovery. All mutable state is confined to the main looper. */
@SuppressLint("MissingPermission") // Permissions are checked at each entry; revocation is handled below.
public final class BluetoothScanService extends Service {
    static final String START = "bluetooth.START", STOP = "bluetooth.STOP", INSPECT = "bluetooth.INSPECT";
    static final int MAX_DEVICES = 512;
    static final class State {
        final LinkedHashMap<String, JSONObject> devices = new LinkedHashMap<>();
        boolean running;
        long revision, started, runId;
        String message = "Not run", inspecting = "";
        int omitted;
        final JSONArray warnings = new JSONArray();
        JSONObject adapterCapabilities = new JSONObject();
    }
    private static State state = new State();
    static State snapshot() { return state; }
    static void clear() { if (!state.running) state = new State(); }
    static String exportJson() {
        return object("schema", 1, "tool", "bluetooth", "startedAt", state.started,
                "running", state.running, "status", state.message, "omittedObservations", state.omitted,
                "devices", new JSONArray(state.devices.values()), "warnings", state.warnings, "adapterCapabilities", state.adapterCapabilities,
                "limitations", "Only observable devices; addresses may rotate; company IDs describe advertisement owners, not verified hardware manufacturers.").toString();
    }
    private final Handler handler = new Handler(Looper.getMainLooper());
    private BluetoothAdapter adapter;
    private BluetoothLeScanner scanner;
    private ScanCallback scanCallback;
    private boolean registered, classicPhase, awaitingSdp;
    private BluetoothGatt gatt;
    private final ArrayDeque<BluetoothGattCharacteristic> reads = new ArrayDeque<>();
    private final Map<BluetoothGattCharacteristic, JSONObject> characteristicRows = new IdentityHashMap<>();
    private BluetoothGattCharacteristic pendingRead;
    private Runnable deadline;
    private long session;
    private final Runnable bleEnd = this::startClassic;
    private final Runnable scanEnd = () -> finish("Discovery complete");
    private final Runnable classicRetry = this::discoverClassic;
    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            if (!state.running) return;
            String action = intent.getAction();
            if (BluetoothAdapter.ACTION_STATE_CHANGED.equals(action)) {
                if (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR) != BluetoothAdapter.STATE_ON)
                    finish("Bluetooth turned off — partial results retained");
                return;
            }
            if (BluetoothAdapter.ACTION_DISCOVERY_FINISHED.equals(action)) {
                if (classicPhase) handler.postDelayed(classicRetry, 2000);
                return;
            }
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            if (device == null) return;
            try {
                if (BluetoothDevice.ACTION_FOUND.equals(action) && classicPhase) {
                    JSONObject row = observe(device, "Classic");
                    if (row == null) return;
                    if (intent.hasExtra(BluetoothDevice.EXTRA_RSSI)) signal(row, intent.getShortExtra(BluetoothDevice.EXTRA_RSSI, (short) 0));
                    String name = intent.getStringExtra(BluetoothDevice.EXTRA_NAME);
                    if (name != null) put(row, "name", name);
                    touch();
                } else if (BluetoothDevice.ACTION_UUID.equals(action)
                        && awaitingSdp && device.getAddress().equals(state.inspecting)) {
                    awaitingSdp = false;
                    JSONObject row = state.devices.get(state.inspecting);
                    Parcelable[] values = intent.getParcelableArrayExtra(BluetoothDevice.EXTRA_UUID);
                    JSONArray uuids = new JSONArray();
                    if (values != null) for (Parcelable value : values) if (value instanceof ParcelUuid) uuids.put(value.toString());
                    put(row, "sdpUuids", uuids);
                    put(row, "sdpStatus", values == null ? "No SDP response; cached UUIDs may still be shown" : "SDP response (Android may return cached UUIDs)");
                    handler.removeCallbacks(deadline);
                    beginGatt(device);
                }
            } catch (SecurityException e) { finish("Bluetooth permission revoked — partial results retained"); }
        }
    };

    @Override public void onCreate() {
        super.onCreate();
        BluetoothManager manager = getSystemService(BluetoothManager.class);
        adapter = manager == null ? null : manager.getAdapter();
        getSystemService(NotificationManager.class).createNotificationChannel(
                new NotificationChannel("bluetooth", "Bluetooth scan", NotificationManager.IMPORTANCE_LOW));
    }

    static boolean permitted(Context context) {
        if (context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) return false;
        return Build.VERSION.SDK_INT < 31 || (context.checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED
                && context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED);
    }

    @Override public int onStartCommand(Intent intent, int flags, int id) {
        if (intent == null) { stopSelf(); return START_NOT_STICKY; }
        String action = intent.getAction();
        if (STOP.equals(action)) {
            if (intent.getLongExtra("runId", -1) == state.runId) finish("Stopped — partial results retained");
            if (!state.running) stopSelf();
            return START_NOT_STICKY;
        }
        if (state.running) return START_NOT_STICKY;
        if (!START.equals(action) && !INSPECT.equals(action)) { stopSelf(); return START_NOT_STICKY; }
        try {
            if (adapter == null || !permitted(this) || !adapter.isEnabled()) {
                state.message = "Enable Bluetooth and grant Bluetooth/location permissions";
                touch(); stopSelf(); return START_NOT_STICKY;
            }
            String address = intent.getStringExtra("address");
            if (INSPECT.equals(action) && !state.devices.containsKey(address)) { stopSelf(); return START_NOT_STICKY; }
            if (START.equals(action)) state = new State();
            state.running = true;
            state.runId = ++session + SystemClock.elapsedRealtimeNanos();
            if (START.equals(action)) state.started = System.currentTimeMillis();
            state.inspecting = INSPECT.equals(action) ? address : "";
            state.message = START.equals(action) ? "Scanning BLE advertisements…" : "Inspecting " + address + "…";
            state.adapterCapabilities = object("ble", getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE),
                    "extendedAdvertising", adapter.isLeExtendedAdvertisingSupported(), "codedPhy", adapter.isLeCodedPhySupported(),
                    "phy2M", adapter.isLe2MPhySupported(), "offloadedFiltering", adapter.isOffloadedFilteringSupported());
            startForeground(2402, notification());
            IntentFilter filter = new IntentFilter();
            filter.addAction(BluetoothDevice.ACTION_FOUND);
            filter.addAction(BluetoothDevice.ACTION_UUID);
            filter.addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED);
            filter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED);
            // Bluetooth broadcasts originate from the privileged Bluetooth process, not this app UID.
            if (Build.VERSION.SDK_INT >= 33) registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
            else registerReceiver(receiver, filter);
            registered = true;
            if (START.equals(action)) {
                int seconds = Math.max(30, Math.min(120, intent.getIntExtra("seconds", 60)));
                if (adapter.isDiscovering()) {
                    finish("Another Bluetooth discovery is active. Stop it and try again.");
                    return START_NOT_STICKY;
                }
                handler.postDelayed(scanEnd, seconds * 1000L);
                for (BluetoothDevice device : adapter.getBondedDevices()) observe(device, "Paired (cached)");
                startBle(adapter.isLeExtendedAdvertisingSupported());
                handler.postDelayed(bleEnd, seconds * 650L);
            } else {
                BluetoothDevice device = adapter.getRemoteDevice(address);
                JSONObject row = state.devices.get(address);
                put(row, "inspectionStatus", "Running");
                if (row.optBoolean("classic") || device.getType() == BluetoothDevice.DEVICE_TYPE_CLASSIC || device.getType() == BluetoothDevice.DEVICE_TYPE_DUAL) {
                    awaitingSdp = true;
                    deadline = () -> { awaitingSdp = false; put(row, "sdpStatus", "SDP timed out; cached UUIDs retained"); beginGatt(device); };
                    handler.postDelayed(deadline, 12000);
                    if (!device.fetchUuidsWithSdp()) { awaitingSdp = false; handler.removeCallbacks(deadline); put(row, "sdpStatus", "SDP could not start"); beginGatt(device); }
                } else beginGatt(device);
            }
            touch();
        } catch (RuntimeException e) { finish("Bluetooth error: " + e.getClass().getSimpleName() + " — " + e.getMessage()); }
        return START_NOT_STICKY;
    }

    private Notification notification() {
        Intent cancel = new Intent(this, BluetoothScanService.class).setAction(STOP).putExtra("runId", state.runId);
        PendingIntent stop = PendingIntent.getService(this, 2402, cancel, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        PendingIntent open = PendingIntent.getActivity(this, 2403, new Intent(this, MainActivity.class), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, "bluetooth").setSmallIcon(R.drawable.ic_scan_notification)
                .setContentTitle("Droidmap Bluetooth").setContentText(state.message).setContentIntent(open)
                .setOngoing(true).addAction(new Notification.Action.Builder(null, "Stop", stop).build()).build();
    }

    private void startBle(boolean extended) {
        scanner = adapter.getBluetoothLeScanner();
        if (scanner == null) { state.warnings.put("BLE scanner unavailable"); state.message = "BLE unavailable; classic discovery will follow"; touch(); return; }
        long run = state.runId;
        scanCallback = new ScanCallback() {
            @Override public void onScanResult(int type, ScanResult result) {
                handler.post(() -> { if (state.running && run == state.runId && !classicPhase) accept(result); });
            }
            @Override public void onBatchScanResults(List<ScanResult> results) { for (ScanResult result : results) onScanResult(0, result); }
            @Override public void onScanFailed(int code) {
                handler.post(() -> { if (state.running && run == state.runId && !classicPhase) {
                    state.warnings.put("BLE scan failed (code " + code + ")" + (extended ? "; retrying legacy BLE" : ""));
                    if (extended) { stopBle(); startBle(false); }
                    else state.message = "BLE scan failed (code " + code + "); classic discovery will follow";
                    touch();
                }});
            }
        };
        android.bluetooth.le.ScanSettings.Builder settings = new android.bluetooth.le.ScanSettings.Builder()
                .setScanMode(android.bluetooth.le.ScanSettings.SCAN_MODE_LOW_LATENCY).setReportDelay(0).setLegacy(!extended);
        if (extended && adapter.isLeCodedPhySupported()) settings.setPhy(android.bluetooth.le.ScanSettings.PHY_LE_ALL_SUPPORTED);
        try { scanner.startScan(Collections.emptyList(), settings.build(), scanCallback); }
        catch (IllegalArgumentException | IllegalStateException error) {
            stopBle();
            state.warnings.put("BLE configuration failed: " + error.getMessage());
            if (extended) startBle(false);
            else state.message = "BLE unavailable; classic discovery will follow";
            touch();
        }
    }

    private void accept(ScanResult result) {
        try {
            JSONObject row = observe(result.getDevice(), "BLE");
            if (row == null) return;
            signal(row, result.getRssi());
            put(row, "connectable", result.isConnectable());
            put(row, "legacyAdvertisement", result.isLegacy());
            put(row, "primaryPhy", result.getPrimaryPhy());
            put(row, "secondaryPhy", result.getSecondaryPhy());
            put(row, "advertisingSid", result.getAdvertisingSid());
            put(row, "periodicInterval", result.getPeriodicAdvertisingInterval());
            put(row, "dataStatus", result.getDataStatus());
            if (result.getTxPower() != ScanResult.TX_POWER_NOT_PRESENT) put(row, "txPower", result.getTxPower());
            ScanRecord record = result.getScanRecord();
            if (record != null) {
                if (record.getDeviceName() != null) put(row, "name", record.getDeviceName());
                if (record.getAdvertiseFlags() >= 0) put(row, "flags", record.getAdvertiseFlags());
                if (record.getTxPowerLevel() != Integer.MIN_VALUE) put(row, "advertisedTxPower", record.getTxPowerLevel());
                addUuids(row, "advertisedServices", record.getServiceUuids());
                if (Build.VERSION.SDK_INT >= 29) addUuids(row, "solicitedServices", record.getServiceSolicitationUuids());
                JSONObject manufacturers = row.optJSONObject("manufacturerData");
                if (manufacturers == null) { manufacturers = new JSONObject(); put(row, "manufacturerData", manufacturers); }
                android.util.SparseArray<byte[]> data = record.getManufacturerSpecificData();
                for (int i = 0; i < data.size() && manufacturers.length() < 64; i++) {
                    int company = data.keyAt(i);
                    String beacon = BluetoothAdvertisement.iBeacon(company, data.valueAt(i));
                    if (!beacon.isEmpty()) put(row, "beacon", beacon);
                    put(manufacturers, String.format(Locale.ROOT, "0x%04X", company), object("company", BluetoothAdvertisement.company(company), "hex", BluetoothAdvertisement.hex(data.valueAt(i))));
                }
                JSONObject serviceData = row.optJSONObject("serviceData");
                if (serviceData == null) { serviceData = new JSONObject(); put(row, "serviceData", serviceData); }
                for (Map.Entry<ParcelUuid, byte[]> entry : record.getServiceData().entrySet()) {
                    if (serviceData.length() >= 64) break;
                    put(serviceData, entry.getKey().toString(), BluetoothAdvertisement.hex(entry.getValue()));
                    String beacon = BluetoothAdvertisement.eddystone(entry.getKey().toString(), entry.getValue());
                    if (!beacon.isEmpty()) put(row, "beacon", beacon);
                }
                String raw = BluetoothAdvertisement.hex(record.getBytes());
                put(row, "lastRawAdvertisement", raw);
                JSONArray samples = row.optJSONArray("rawSamples");
                if (samples == null) { samples = new JSONArray(); put(row, "rawSamples", samples); }
                if (samples.length() < 8 && !contains(samples, raw)) samples.put(raw);
                BluetoothAdvertisement.Parsed parsed = BluetoothAdvertisement.parse(record.getBytes());
                JSONArray fields = new JSONArray();
                for (BluetoothAdvertisement.Field field : parsed.fields()) fields.put(object("type", field.type(), "hex", field.hex()));
                put(row, "adStructures", fields);
                put(row, "truncatedAdvertisement", parsed.truncated());
            }
            touch();
        } catch (SecurityException e) { finish("Bluetooth permission revoked — partial results retained"); }
    }

    private JSONObject observe(BluetoothDevice device, String source) {
        String address = device.getAddress();
        JSONObject row = state.devices.get(address);
        if (row == null) {
            if (state.devices.size() >= MAX_DEVICES) { state.omitted++; touch(); return null; }
            row = object("address", address, "firstSeen", System.currentTimeMillis(), "observations", 0);
            state.devices.put(address, row);
        }
        JSONArray sources = row.optJSONArray("sources");
        if (sources == null) { sources = new JSONArray(); put(row, "sources", sources); }
        if (!contains(sources, source)) sources.put(source);
        if (!source.startsWith("Paired")) {
            put(row, "lastSeen", System.currentTimeMillis());
            put(row, "observations", row.optInt("observations") + 1);
        }
        if (source.equals("BLE")) put(row, "ble", true);
        if (source.equals("Classic")) put(row, "classic", true);
        if (!row.has("name") && device.getName() != null) put(row, "name", device.getName());
        put(row, "type", switch (device.getType()) {
            case BluetoothDevice.DEVICE_TYPE_CLASSIC -> "Classic";
            case BluetoothDevice.DEVICE_TYPE_LE -> "BLE";
            case BluetoothDevice.DEVICE_TYPE_DUAL -> "Dual";
            default -> "Unknown";
        });
        put(row, "bond", device.getBondState() == BluetoothDevice.BOND_BONDED ? "Paired" : device.getBondState() == BluetoothDevice.BOND_BONDING ? "Pairing" : "Not paired");
        BluetoothClass klass = device.getBluetoothClass();
        if (klass != null) { put(row, "deviceClass", klass.getDeviceClass()); put(row, "majorClass", klass.getMajorDeviceClass()); }
        ParcelUuid[] cached = device.getUuids();
        if (cached != null) addUuids(row, "cachedUuids", Arrays.asList(cached));
        return row;
    }

    private void signal(JSONObject row, int rssi) {
        put(row, "rssi", rssi);
        put(row, "minRssi", Math.min(row.optInt("minRssi", rssi), rssi));
        put(row, "maxRssi", Math.max(row.optInt("maxRssi", rssi), rssi));
    }

    private void startClassic() {
        if (!state.running) return;
        stopBle();
        classicPhase = true;
        state.message = "Scanning Bluetooth Classic (BLE phase finished)…";
        discoverClassic(); touch();
        getSystemService(NotificationManager.class).notify(2402, notification());
    }

    private void discoverClassic() {
        if (!state.running || !classicPhase) return;
        try {
            if (!adapter.startDiscovery()) { state.warnings.put("Classic discovery could not start"); state.message = "Classic discovery could not start; partial BLE results retained"; touch(); }
        } catch (RuntimeException e) { finish("Classic discovery failed: " + e.getMessage()); }
    }

    private void beginGatt(BluetoothDevice device) {
        if (!state.running || !device.getAddress().equals(state.inspecting)) return;
        JSONObject row = state.devices.get(state.inspecting);
        if (!row.optBoolean("ble") && device.getType() != BluetoothDevice.DEVICE_TYPE_LE && device.getType() != BluetoothDevice.DEVICE_TYPE_DUAL) {
            put(row, "gattStatus", "Not a known BLE device"); finish("Service inspection finished"); return;
        }
        if (row.has("connectable") && !row.optBoolean("connectable")) {
            put(row, "gattStatus", "Advertisement is not connectable"); finish("Service inspection finished"); return;
        }
        put(row, "gattStatus", "Connecting for read-only service discovery…"); touch();
        final long run = state.runId;
        deadline = () -> finish("GATT inspection timed out — partial results retained");
        handler.postDelayed(deadline, 25000);
        BluetoothGattCallback callback = new BluetoothGattCallback() {
            private void dispatch(BluetoothGatt connection, Runnable work) {
                handler.post(() -> { if (state.running && state.runId == run && connection == gatt) {
                    try { work.run(); } catch (RuntimeException e) { finish("GATT error: " + e.getMessage()); }
                }});
            }
            @Override public void onConnectionStateChange(BluetoothGatt connection, int status, int newState) {
                dispatch(connection, () -> {
                    if (status != BluetoothGatt.GATT_SUCCESS || newState == BluetoothProfile.STATE_DISCONNECTED) {
                        put(row, "gattStatus", "Disconnected (status " + status + ")"); finish("GATT disconnected — partial results retained");
                    } else if (newState == BluetoothProfile.STATE_CONNECTED && !connection.discoverServices()) finish("GATT service discovery could not start");
                });
            }
            @Override public void onServicesDiscovered(BluetoothGatt connection, int status) {
                dispatch(connection, () -> {
                    if (status != BluetoothGatt.GATT_SUCCESS) { finish("GATT service discovery failed (status " + status + ")"); return; }
                    JSONArray services = new JSONArray();
                    int count = 0;
                    for (BluetoothGattService service : connection.getServices()) {
                        if (services.length() >= 128) { put(row, "gattTruncated", true); break; }
                        JSONArray chars = new JSONArray();
                        for (BluetoothGattCharacteristic characteristic : service.getCharacteristics()) {
                            if (++count > 512) { put(row, "gattTruncated", true); break; }
                            JSONArray descriptors = new JSONArray();
                            for (BluetoothGattDescriptor descriptor : characteristic.getDescriptors()) {
                                if (descriptors.length() >= 64) { put(row, "gattTruncated", true); break; }
                                descriptors.put(descriptor.getUuid().toString());
                            }
                            JSONObject detail = object("uuid", characteristic.getUuid().toString(), "instanceId", characteristic.getInstanceId(),
                                    "name", BluetoothAdvertisement.uuidName(characteristic.getUuid().toString()), "properties", characteristic.getProperties(), "descriptors", descriptors);
                            chars.put(detail);
                            if ((characteristic.getProperties() & BluetoothGattCharacteristic.PROPERTY_READ) != 0
                                    && reads.size() < 32 && BluetoothAdvertisement.readableInfo(service.getUuid().toString(), characteristic.getUuid().toString())) {
                                reads.add(characteristic); characteristicRows.put(characteristic, detail);
                            }
                        }
                        services.put(object("uuid", service.getUuid().toString(), "instanceId", service.getInstanceId(),
                                "name", BluetoothAdvertisement.uuidName(service.getUuid().toString()), "type", service.getType(), "characteristics", chars));
                    }
                    put(row, "gattServices", services); put(row, "gattStatus", "Services discovered; reading public device information"); touch(); readNext();
                });
            }
            @Override public void onCharacteristicRead(BluetoothGatt connection, BluetoothGattCharacteristic characteristic, byte[] value, int status) {
                dispatch(connection, () -> readResult(characteristic, value, status));
            }
            @SuppressWarnings("deprecation")
            @Override public void onCharacteristicRead(BluetoothGatt connection, BluetoothGattCharacteristic characteristic, int status) {
                if (Build.VERSION.SDK_INT < 33) {
                    byte[] value = characteristic.getValue();
                    dispatch(connection, () -> readResult(characteristic, value, status));
                }
            }
        };
        try { gatt = device.connectGatt(this, false, callback, BluetoothDevice.TRANSPORT_LE); }
        catch (RuntimeException e) { finish("GATT connection failed: " + e.getMessage()); }
        if (gatt == null) finish("GATT connection could not start");
    }

    private void readResult(BluetoothGattCharacteristic characteristic, byte[] value, int status) {
        if (characteristic != pendingRead) return;
        JSONObject detail = characteristicRows.get(characteristic);
        put(detail, "readStatus", status);
        if (status == BluetoothGatt.GATT_SUCCESS) {
            put(detail, "hex", BluetoothAdvertisement.hex(value));
            put(detail, "value", BluetoothAdvertisement.value(characteristic.getUuid().toString(), value));
        }
        pendingRead = null; touch(); readNext();
    }

    private void readNext() {
        if (reads.isEmpty()) {
            put(state.devices.get(state.inspecting), "gattStatus", "Read-only inspection complete"); finish("Service inspection finished"); return;
        }
        pendingRead = reads.remove();
        if (!gatt.readCharacteristic(pendingRead)) {
            put(characteristicRows.get(pendingRead), "readStatus", "Could not start");
            pendingRead = null; readNext();
        }
    }

    private void stopBle() {
        if (scanner != null && scanCallback != null) {
            try { scanner.stopScan(scanCallback); } catch (RuntimeException ignored) { }
        }
        scanner = null; scanCallback = null;
    }

    private void release() {
        handler.removeCallbacksAndMessages(null);
        stopBle();
        if (adapter != null && classicPhase) { try { adapter.cancelDiscovery(); } catch (RuntimeException ignored) { } }
        classicPhase = false; awaitingSdp = false;
        if (gatt != null) {
            BluetoothGatt connection = gatt; gatt = null;
            try { connection.disconnect(); } catch (RuntimeException ignored) { }
            try { connection.close(); } catch (RuntimeException ignored) { }
        }
        reads.clear(); characteristicRows.clear(); pendingRead = null;
        if (registered) { unregisterReceiver(receiver); registered = false; }
    }

    private void finish(String message) {
        JSONObject row = state.devices.get(state.inspecting);
        if (row != null) put(row, "inspectionStatus", message);
        state.running = false; state.inspecting = ""; state.message = message + (state.warnings.length() > 0 ? " • " + state.warnings.length() + " warning(s); see export" : ""); touch();
        release(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf();
    }
    private void touch() { state.revision++; }
    static JSONObject object(Object... entries) {
        JSONObject result = new JSONObject();
        for (int i = 0; i < entries.length; i += 2) put(result, (String) entries[i], entries[i + 1]);
        return result;
    }
    static void put(JSONObject object, String key, Object value) {
        if (object == null) return;
        try { object.put(key, value); } catch (JSONException e) { throw new IllegalArgumentException(e); }
    }
    private static boolean contains(JSONArray array, String value) {
        for (int i = 0; i < array.length(); i++) if (value.equals(array.optString(i))) return true;
        return false;
    }
    private static void addUuids(JSONObject row, String key, List<ParcelUuid> values) {
        if (values == null) return;
        JSONArray array = row.optJSONArray(key);
        if (array == null) { array = new JSONArray(); put(row, key, array); }
        for (ParcelUuid value : values) if (array.length() < 128 && !contains(array, value.toString())) array.put(value.toString());
    }
    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public void onDestroy() {
        if (state.running) { state.running = false; state.message = "Interrupted — partial results retained"; state.inspecting = ""; touch(); }
        release(); super.onDestroy();
    }
}
