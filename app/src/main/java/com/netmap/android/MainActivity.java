package com.netmap.android;

import android.app.Activity;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
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

public final class MainActivity extends Activity {
    private EditText target;
    private Button start;
    private TextView settingsSummary;
    private LinearLayout deviceList;
    private ScrollView resultsScroll;
    private final Set<String> expandedDevices=new HashSet<>();
    private String selectedPorts=ScanPlan.FAST_PORTS;
    private int timeoutMs=200;
    private ScanPlan.Mode selectedMode=ScanPlan.Mode.FAST;
    private boolean adaptiveScan=true;
    private String pendingExport="";
    private long pendingExportRunId;
    private ScanHistory history;
    private List<String> lastDevices=new ArrayList<>();
    private TextView status;
    private ProgressBar progress;
    private boolean scanRunning, startingScan;
    private ScanSnapshot launchPrevious;
    private Intent pendingScan;
    private ScanSnapshot displayedSnapshot;
    private final android.os.Handler uiHandler=new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable refreshScan=new Runnable() {
        public void run() {
            ScanSnapshot snapshot=ScanService.snapshot();
            if(snapshot!=null && snapshot!=displayedSnapshot) applySnapshot(snapshot);
            uiHandler.postDelayed(this,500);
        }
    };
    private final ExecutorService background = Executors.newSingleThreadExecutor();
    private volatile boolean destroyed;
    private String report = "";
    private String resultText = "";

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN | android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        history=new ScanHistory(new java.io.File(getFilesDir(),"scan-history.json"));
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setFocusableInTouchMode(true);
        int pad = (int)(16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        layout.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(pad + insets.getSystemWindowInsetLeft(), pad + insets.getSystemWindowInsetTop(),
                pad + insets.getSystemWindowInsetRight(), pad + insets.getSystemWindowInsetBottom());
            return insets;
        });
        android.content.SharedPreferences preferences=getPreferences(MODE_PRIVATE);
        selectedPorts=preferences.getString("ports",ScanPlan.FAST_PORTS);
        timeoutMs=preferences.getInt("timeout",200);
        if(!preferences.getBoolean("timeoutDefault200",false)) {
            if(timeoutMs==500) timeoutMs=200;
            preferences.edit().putInt("timeout",timeoutMs).putBoolean("timeoutDefault200",true).apply();
        }
        selectedMode=preferences.getBoolean("complete",false)?ScanPlan.Mode.COMPLETE:ScanPlan.Mode.FAST;
        adaptiveScan=preferences.getBoolean("adaptive",true);
        LinearLayout header=new LinearLayout(this); header.setGravity(android.view.Gravity.CENTER_VERTICAL);
        TextView title=new TextView(this); title.setText("Droidmap"); title.setTextSize(26);
        header.addView(title,new LinearLayout.LayoutParams(0,-2,1));
        Button options=new Button(this); options.setText("Options"); options.setContentDescription("Open options menu");
        header.addView(options); layout.addView(header); options.setOnClickListener(this::showOptions);
        target=field(layout,"Target IP or private network (/24–/32)","192.168.0.0/24",R.id.target);
        settingsSummary=new TextView(this); settingsSummary.setTextSize(13); settingsSummary.setPadding(0,pad/2,0,pad/2);
        layout.addView(settingsSummary); updateSettingsSummary();
        start=new Button(this); start.setText("Start scan"); layout.addView(start);
        start.setOnClickListener(v -> {
            if(!scanRunning) begin();
            else {
                ScanSnapshot snapshot=ScanService.snapshot();
                if(snapshot!=null && snapshot.running) startService(new Intent(this,ScanService.class).setAction(ScanService.CANCEL).putExtra("runId",snapshot.runId));
                start.setEnabled(false); status.setText("Cancelling…");
            }
        });
        progress=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal); progress.setVisibility(android.view.View.GONE); layout.addView(progress);
        status=new TextView(this); status.setText("Ready"); status.setPadding(0,pad/2,0,pad/2); status.setAccessibilityLiveRegion(android.view.View.ACCESSIBILITY_LIVE_REGION_POLITE); layout.addView(status);
        ScrollView scroll=new ScrollView(this); resultsScroll=scroll; scroll.setFillViewport(true);
        deviceList=new LinearLayout(this); deviceList.setOrientation(LinearLayout.VERTICAL); scroll.addView(deviceList);
        layout.addView(scroll,new LinearLayout.LayoutParams(-1,0,1)); setContentView(layout);
        if(state!=null) {
            pendingScan=state.getParcelable("pendingScan");
            pendingExport=state.getString("pendingExport", "");
            pendingExportRunId=state.getLong("pendingExportRunId",0);
            ArrayList<String> expanded=state.getStringArrayList("expandedDevices");
            if(expanded!=null) expandedDevices.addAll(expanded);

        }
        renderDevices();
        background.execute(() -> {
            try {
                ScanSnapshot saved=new LatestScanStore(new java.io.File(getFilesDir(),"latest-scan.json")).load();
                runOnUiThread(() -> {
                    if(destroyed) return;
                    ScanSnapshot live=ScanService.snapshot(); applySnapshot(live==null?saved:live);
                });
            } catch(Exception e) { runOnUiThread(() -> {if(!destroyed && ScanService.snapshot()==null) status.setText("Saved result unavailable");}); }
        });
    }
    @Override protected void onStart() { super.onStart(); uiHandler.post(refreshScan); }
    @Override protected void onStop() { uiHandler.removeCallbacks(refreshScan); super.onStop(); }
    private void applySnapshot(ScanSnapshot snapshot) {
        if(startingScan && (snapshot==launchPrevious || ScanService.snapshot()==null)) return;
        startingScan=false;
        displayedSnapshot=snapshot; scanRunning=snapshot.running;
        start.setText(scanRunning?"Cancel scan":"Start scan"); start.setEnabled(!scanRunning || snapshot.cancellable);
        target.setEnabled(!scanRunning); progress.setVisibility(scanRunning?android.view.View.VISIBLE:android.view.View.GONE);
        progress.setMax(snapshot.total); progress.setProgress(snapshot.done); status.setText(snapshot.message);
        if(scanRunning) target.setText(snapshot.target);
        if(!report.equals(snapshot.report)) { report=snapshot.report; resultText=snapshot.text; renderDevices(); }
        else resultText=snapshot.text;
    }
    private void updateSettingsSummary() {
        int count=ScanPlan.parsePorts(selectedPorts).size();
        settingsSummary.setText((selectedMode==ScanPlan.Mode.FAST?"Fast":"Complete")+" • "+count+" ports • "+timeoutMs+" ms"+(adaptiveScan?" • Adaptive":""));
    }
    private void showOptions(android.view.View anchor) {
        PopupMenu menu=new PopupMenu(this,anchor); boolean idle=!scanRunning;
        menu.getMenu().add(0,1,0,"Scan settings").setEnabled(idle);
        menu.getMenu().add(0,2,1,"Use Wi-Fi network").setEnabled(idle);
        menu.getMenu().add(0,3,2,"History").setEnabled(idle);
        menu.getMenu().add(0,4,3,"Reanalyze a device").setEnabled(idle && !lastDevices.isEmpty());
        menu.getMenu().add(0,5,4,"Full report").setEnabled(!resultText.isEmpty());
        menu.getMenu().add(0,6,5,"Export JSON").setEnabled(idle && !report.isEmpty());
        menu.setOnMenuItemClickListener(item -> {
            switch(item.getItemId()) {
                case 1: showSettings(); break;
                case 2: suggestWifi(); break;
                case 3: showHistory(); break;
                case 4: chooseDevice(); break;
                case 5: showText("Full report",resultText); break;
                case 6:
                    pendingExport=report; pendingExportRunId=displayedSnapshot==null?0:displayedSnapshot.runId;
                    Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE);
                    intent.putExtra(Intent.EXTRA_TITLE,"droidmap-scan.json"); startActivityForResult(intent,10); break;
                default: return false;
            }
            return true;
        }); menu.show();
    }
    private void showSettings() {
        if(scanRunning) return;
        LinearLayout form=new LinearLayout(this); form.setOrientation(LinearLayout.VERTICAL);
        int pad=(int)(20*getResources().getDisplayMetrics().density); form.setPadding(pad,0,pad,0);
        TextView label=new TextView(this); label.setText("Scan mode"); form.addView(label);
        Spinner mode=new Spinner(this);
        mode.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,new String[]{"Fast","Complete"}));
        mode.setSelection(selectedMode==ScanPlan.Mode.FAST?0:1); form.addView(mode);
        EditText ports=field(form,"TCP ports (comma-separated or ranges)",selectedPorts,R.id.ports);
        EditText timeout=field(form,"Connection timeout (100–3000 ms)",Integer.toString(timeoutMs),R.id.timeout); timeout.setInputType(InputType.TYPE_CLASS_NUMBER);
        CheckBox adaptive=new CheckBox(this); adaptive.setText("Adaptive scan (prioritize responders)"); adaptive.setChecked(adaptiveScan); form.addView(adaptive);
        TextView help=new TextView(this); help.setText("Complete mode uses more default ports, retries and longer device discovery. Custom ports are kept."); form.addView(help);
        mode.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            public void onNothingSelected(AdapterView<?> parent) { }
            public void onItemSelected(AdapterView<?> parent,android.view.View view,int position,long id) {
                String current=ports.getText().toString();
                if(current.equals(ScanPlan.FAST_PORTS)||current.equals(ScanPlan.COMPLETE_PORTS)) ports.setText(position==0?ScanPlan.FAST_PORTS:ScanPlan.COMPLETE_PORTS);
            }
        });
        ScrollView scroll=new ScrollView(this); scroll.addView(form);
        android.app.AlertDialog dialog=new android.app.AlertDialog.Builder(this).setTitle("Scan settings").setView(scroll)
            .setNegativeButton("Cancel",null).setPositiveButton("Save",null).create();
        dialog.setOnShowListener(ignored -> dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            int value;
            try { value=Integer.parseInt(timeout.getText().toString().trim()); if(value<100||value>3000) throw new IllegalArgumentException(); }
            catch(IllegalArgumentException e) { timeout.setError("Enter 100–3000 ms"); return; }
            String portValues=ports.getText().toString().trim();
            try { ScanPlan.parsePorts(portValues); } catch(IllegalArgumentException e) { ports.setError(e.getMessage()); return; }
            selectedPorts=portValues; timeoutMs=value; selectedMode=mode.getSelectedItemPosition()==0?ScanPlan.Mode.FAST:ScanPlan.Mode.COMPLETE; adaptiveScan=adaptive.isChecked();
            saveSettings(); updateSettingsSummary(); dialog.dismiss();
        })); dialog.show();
    }
    private void saveSettings() {
        getPreferences(MODE_PRIVATE).edit().putString("ports",selectedPorts).putInt("timeout",timeoutMs)
            .putBoolean("complete",selectedMode==ScanPlan.Mode.COMPLETE).putBoolean("adaptive",adaptiveScan).apply();
    }
    private void showText(String title,String text) {
        ScrollView scroll=new ScrollView(this); TextView content=new TextView(this); content.setText(text); content.setTextIsSelectable(true);
        int pad=(int)(20*getResources().getDisplayMetrics().density); content.setPadding(pad,pad,pad,pad); scroll.addView(content);
        new android.app.AlertDialog.Builder(this).setTitle(title).setView(scroll).setPositiveButton("Close",null).show();
    }
    private void renderDevices() {
        int scrollPosition=resultsScroll.getScrollY();
        deviceList.removeAllViews(); lastDevices=new ArrayList<>();
        if(report.isEmpty()) { TextView empty=new TextView(this); empty.setText("Discover devices on your local network.\nUse Options to adjust the scan."); deviceList.addView(empty); return; }
        try {
            JSONObject data=new JSONObject(report); JSONArray devices=data.getJSONArray("devices");
            TextView heading=new TextView(this); heading.setText(devices.length()+(data.optBoolean("partial")?" devices so far • ":" devices • ")+data.optString("target")); heading.setTextSize(18); deviceList.addView(heading);
            if(devices.length()==0) { TextView empty=new TextView(this); empty.setText("No devices identified. See Full report in Options for scan details."); deviceList.addView(empty); }
            Map<String,Set<Integer>> portsByIp=new HashMap<>();
            for(String key:new String[]{"checks","advertisedEndpointChecks"}) {
                JSONArray checks=data.optJSONArray(key); if(checks==null) continue;
                for(int j=0;j<checks.length();j++) { JSONObject check=checks.getJSONObject(j); if("OPEN".equals(check.optString("state"))) portsByIp.computeIfAbsent(check.getString("ip"),ignored -> new TreeSet<>()).add(check.getInt("port")); }
            }
            for(int i=0;i<devices.length();i++) {
                JSONObject device=devices.getJSONObject(i); String ip=device.getString("ip"); lastDevices.add(ip);
                Set<Integer> openPorts=portsByIp.getOrDefault(ip,Collections.emptySet());
                addDeviceCard(device,openPorts);
            }
            TextView footer=new TextView(this); footer.setText("Tap a device to expand or collapse details.\nFull report and JSON export are in Options."); deviceList.addView(footer);
        } catch(Exception e) { TextView fallback=new TextView(this); fallback.setText("Summary unavailable. Open Full report in Options."); deviceList.addView(fallback); }
        resultsScroll.post(() -> resultsScroll.scrollTo(0,scrollPosition));
    }
    private int dp(int value) { return Math.round(value*getResources().getDisplayMetrics().density); }
    private String portList(Set<Integer> ports,int limit) {
        if(ports.isEmpty()) return "None observed";
        StringBuilder value=new StringBuilder(); int count=0;
        for(int port:ports) { if(count==limit) break; if(count++>0) value.append(", "); value.append(port); }
        if(ports.size()>limit) value.append(" (+").append(ports.size()-limit).append(" more)");
        return value.toString();
    }
    private void addDeviceCard(JSONObject device,Set<Integer> openPorts) {
        String ip=device.optString("ip");
        String name=device.optString("reportedName").replaceAll("\\s+"," ").trim();
        if(name.length()>64) name=name.substring(0,61)+"…";
        String summary=ip+(name.isEmpty()?"":" • "+name)+"\nProbable type: "+device.optString("probableType","Unknown")
            +"\nOpen TCP ports: "+portList(openPorts,8);
        LinearLayout card=new LinearLayout(this); card.setOrientation(LinearLayout.VERTICAL);
        android.graphics.drawable.GradientDrawable shape=new android.graphics.drawable.GradientDrawable();
        shape.setColor(android.graphics.Color.rgb(20,20,20)); shape.setCornerRadius(dp(12)); shape.setStroke(dp(1),android.graphics.Color.rgb(55,55,55)); card.setBackground(shape);
        LinearLayout.LayoutParams margins=new LinearLayout.LayoutParams(-1,-2); margins.setMargins(0,dp(10),0,0); deviceList.addView(card,margins);
        Button toggle=new Button(this); toggle.setAllCaps(false); toggle.setGravity(android.view.Gravity.START|android.view.Gravity.CENTER_VERTICAL);
        toggle.setTextSize(16); toggle.setPadding(dp(16),dp(12),dp(16),dp(12)); toggle.setMinHeight(dp(64)); card.addView(toggle,new LinearLayout.LayoutParams(-1,-2));
        LinearLayout details=new LinearLayout(this); details.setOrientation(LinearLayout.VERTICAL); details.setPadding(dp(16),0,dp(16),dp(16)); card.addView(details);
        boolean expanded=expandedDevices.contains(ip);
        if(expanded) populateDeviceDetails(details,device,openPorts);
        details.setVisibility(expanded?android.view.View.VISIBLE:android.view.View.GONE);
        setExpansionLabel(toggle,summary,ip,expanded);
        toggle.setOnClickListener(v -> {
            boolean show=details.getVisibility()!=android.view.View.VISIBLE;
            if(show && details.getChildCount()==0) populateDeviceDetails(details,device,openPorts);
            details.setVisibility(show?android.view.View.VISIBLE:android.view.View.GONE);
            if(show) expandedDevices.add(ip); else expandedDevices.remove(ip);
            setExpansionLabel(toggle,summary,ip,show);
        });
    }
    private void setExpansionLabel(Button toggle,String summary,String ip,boolean expanded) {
        toggle.setText(summary+"\n"+(expanded?"▾ Hide details":"▸ Show details"));
        toggle.setContentDescription(summary+". "+(expanded?"Collapse":"Expand")+" details for "+ip);
    }
    private void detailSection(LinearLayout parent,String title) {
        TextView heading=new TextView(this); heading.setText(title); heading.setTextSize(16); heading.setTypeface(null,android.graphics.Typeface.BOLD);
        heading.setPadding(0,dp(16),0,dp(6)); parent.addView(heading);
    }
    private void detailValue(LinearLayout parent,String label,String value) {
        if(value.isEmpty()) return;
        TextView caption=new TextView(this); caption.setText(label); caption.setTextSize(12); caption.setTextColor(android.graphics.Color.LTGRAY); caption.setPadding(0,dp(8),0,dp(2)); parent.addView(caption);
        TextView content=new TextView(this); content.setText(value); content.setTextSize(15); content.setTextIsSelectable(true); parent.addView(content);
    }
    private void populateDeviceDetails(LinearLayout details,JSONObject device,Set<Integer> openPorts) {
        detailSection(details,"Open TCP ports");
        detailValue(details,"Observed ports ("+openPorts.size()+")",portList(openPorts,Integer.MAX_VALUE));
        detailSection(details,"Device identity");
        detailValue(details,"IP address",device.optString("ip"));
        String[] keys={"reportedName","reportedManufacturer","reportedModel","reportedMac","dnsHostname","probableType","identityConfidence","suggestedManufacturer"};
        String[] labels={"Name (reported)","Manufacturer (reported)","Model (reported)","MAC (reported)","DNS hostname (reported)","Probable type","Identity confidence","Suggested manufacturer"};
        for(int i=0;i<keys.length;i++) detailValue(details,labels[i],device.optString(keys[i]));
        JSONArray reasons=device.optJSONArray("identificationReasons");
        if(reasons!=null && reasons.length()>0) {
            detailSection(details,"Identification reasons");
            for(int i=0;i<reasons.length();i++) detailValue(details,"Reason "+(i+1),reasons.optString(i));
        }
        Map<String,List<JSONObject>> sources=new LinkedHashMap<>(); JSONArray observations=device.optJSONArray("evidence");
        if(observations!=null) for(int i=0;i<observations.length();i++) {
            JSONObject item=observations.optJSONObject(i); if(item!=null) sources.computeIfAbsent(item.optString("source","Unknown source"),ignored -> new ArrayList<>()).add(item);
        }
        detailSection(details,"Evidence by source");
        if(sources.isEmpty()) detailValue(details,"Evidence","No identification metadata collected.");
        for(Map.Entry<String,List<JSONObject>> source:sources.entrySet()) {
            detailSection(details,source.getKey());
            for(JSONObject item:source.getValue()) detailValue(details,evidenceLabel(item.optString("field")),item.optString("value"));
        }
        detailValue(details,"Interpretation","Names, models and MAC addresses are self-reported. Device type and suggested identity are inferred; open ports do not establish vulnerabilities.");
    }
    private String evidenceLabel(String field) {
        // Keep unknown protocol fields readable without discarding their original name.
        String label=field.replaceAll("([a-z0-9])([A-Z])","$1 $2").replace('_',' ');
        return label.isEmpty()?"Observation":Character.toUpperCase(label.charAt(0))+label.substring(1);
    }
    private void chooseDevice() {
        if(scanRunning || lastDevices.isEmpty()) return;
        String[] ips=lastDevices.toArray(new String[0]);
        new android.app.AlertDialog.Builder(this).setTitle("Reanalyze a device")
            .setItems(ips,(dialog,index)-> {target.setText(ips[index]); selectedMode=ScanPlan.Mode.COMPLETE; selectedPorts=ScanPlan.COMPLETE_PORTS; saveSettings(); updateSettingsSummary(); begin();})
            .setNegativeButton("Cancel",null).show();
    }
    private void showHistory() {
        if(scanRunning) return;
        background.execute(()-> {
            try {
                JSONArray entries=history.load();String[] labels=new String[entries.length()];
                for(int i=0;i<entries.length();i++) {JSONObject entry=entries.getJSONObject(i); labels[i]=new java.text.SimpleDateFormat("MM-dd HH:mm",Locale.US).format(new Date(entry.getLong("time")))+" • "+entry.getString("target");}
                runOnUiThread(()-> {
                    if(destroyed || scanRunning) return;
                    if(labels.length==0) {new android.app.AlertDialog.Builder(this).setMessage("No completed scans saved yet.").setPositiveButton("OK",null).show();return;}
                    new android.app.AlertDialog.Builder(this).setTitle("Recent scans")
                        .setItems(labels,(dialog,index)-> {try {new android.app.AlertDialog.Builder(this).setTitle("Scan summary").setMessage(ScanHistory.describe(entries.getJSONObject(index))).setPositiveButton("OK",null).show();}catch(Exception ignored){}})
                        .setNegativeButton("Close",null).show();
                });
            } catch(Exception e) {runOnUiThread(()-> {if(!destroyed) status.setText("History unavailable");});}
        });
    }
    private EditText field(LinearLayout layout, String label, String value, int id) {
        TextView caption = new TextView(this); caption.setText(label); caption.setLabelFor(id); layout.addView(caption);
        EditText field = new EditText(this); field.setId(id); field.setSingleLine(true); field.setText(value); layout.addView(field); return field;
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
        String targetValue=target.getText().toString().trim();
        try { new ScanPlan(targetValue,selectedPorts,timeoutMs,selectedMode,adaptiveScan); }
        catch(IllegalArgumentException e) { target.setError(e.getMessage()); return; }
        Intent request=new Intent(this,ScanService.class).setAction(ScanService.START)
            .putExtra("target",targetValue).putExtra("ports",selectedPorts).putExtra("timeout",timeoutMs)
            .putExtra("complete",selectedMode==ScanPlan.Mode.COMPLETE).putExtra("adaptive",adaptiveScan);
        if(android.os.Build.VERSION.SDK_INT>=33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED
            && !getPreferences(MODE_PRIVATE).getBoolean("notificationAsked",false)) {
            pendingScan=request;
            requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS},20); return;
        }
        launchScan(request);
    }
    @Override public void onRequestPermissionsResult(int request,String[] permissions,int[] results) {
        super.onRequestPermissionsResult(request,permissions,results);
        if(request!=20) return;
        getPreferences(MODE_PRIVATE).edit().putBoolean("notificationAsked",true).apply();
        Intent scan=pendingScan; pendingScan=null;
        if(scan!=null) launchScan(scan);
        if(results.length==0 || results[0]!=android.content.pm.PackageManager.PERMISSION_GRANTED)
            Toast.makeText(this,"Notifications are off. Scan progress and cancellation remain available in the app.",Toast.LENGTH_LONG).show();
    }
    private void launchScan(Intent request) {
        android.view.inputmethod.InputMethodManager keyboard=(android.view.inputmethod.InputMethodManager)getSystemService(INPUT_METHOD_SERVICE);
        if(keyboard!=null) keyboard.hideSoftInputFromWindow(target.getWindowToken(),0);
        target.clearFocus();
        try {
            launchPrevious=ScanService.snapshot(); displayedSnapshot=launchPrevious; startingScan=true;
            startForegroundService(request);
            scanRunning=true; expandedDevices.clear(); report=""; resultText=""; deviceList.removeAllViews(); lastDevices.clear();
            start.setText("Cancel scan"); start.setEnabled(false); target.setEnabled(false); status.setText("Starting scan…");
        } catch(RuntimeException e) { startingScan=false; scanRunning=false; start.setText("Start scan"); start.setEnabled(true); target.setEnabled(true); status.setText("Unable to start scan: "+e.getMessage()); }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if(request!=10) return;
        if(result!=RESULT_OK || data==null || data.getData()==null) { pendingExport=""; pendingExportRunId=0; return; }
        final android.net.Uri uri=data.getData(); final String snapshot=pendingExport; final long exportId=pendingExportRunId;
        pendingExport=""; pendingExportRunId=0;
        background.execute(() -> {
            try {
                String payload=snapshot;
                if(payload.isEmpty()) {
                    ScanSnapshot saved=ScanService.snapshot();
                    if(saved==null || saved.runId!=exportId) saved=new LatestScanStore(new java.io.File(getFilesDir(),"latest-scan.json")).load();
                    if(saved.runId!=exportId || saved.report.isEmpty()) throw new java.io.IOException("Export snapshot no longer available");
                    payload=saved.report;
                }
                try(OutputStream stream=getContentResolver().openOutputStream(uri,"wt")) {
                    if(stream==null) throw new java.io.IOException("Unable to open destination");
                    stream.write(payload.getBytes(StandardCharsets.UTF_8));
                }
                runOnUiThread(() -> {if(!destroyed) status.setText("JSON report saved");});
            } catch(Exception e) {runOnUiThread(() -> {if(!destroyed) status.setText("Export failed: "+e.getMessage());});}
        });
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        state.putStringArrayList("expandedDevices",new ArrayList<>(expandedDevices));
        if(pendingScan!=null) state.putParcelable("pendingScan",pendingScan);
        if(pendingExport.length()<100000) state.putString("pendingExport",pendingExport);
        state.putLong("pendingExportRunId",pendingExportRunId);
    }
    @Override protected void onDestroy() {
        destroyed=true; uiHandler.removeCallbacks(refreshScan); background.shutdown(); super.onDestroy();
    }
}
