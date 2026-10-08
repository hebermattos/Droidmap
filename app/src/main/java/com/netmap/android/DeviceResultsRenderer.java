package com.netmap.android;

import android.content.Context;
import android.graphics.Color;
import android.view.View;
import android.widget.*;
import org.json.*;
import java.util.*;

/** Compact report cards and filters; retains full evidence behind expandable sections. */
final class DeviceResultsRenderer {
    private final Context context;
    private final LinearLayout deviceList;
    private final ScrollView resultsScroll;
    private final Set<String> expandedDevices;
    private final Map<String,Boolean> sectionStates=new HashMap<>();
    private final java.util.function.Consumer<String> openNmapOutput;
    private ReportPresentation.Filter filter=ReportPresentation.Filter.ALL;
    private String lastReport="";
    private List<String> lastDevices=new ArrayList<>();

    DeviceResultsRenderer(Context context,LinearLayout deviceList,ScrollView resultsScroll,
            Set<String> expandedDevices,java.util.function.Consumer<String> openNmapOutput) {
        this.context=context;this.deviceList=deviceList;this.resultsScroll=resultsScroll;
        this.expandedDevices=expandedDevices;this.openNmapOutput=openNmapOutput;
    }
    List<String> render(String report) {
        int scrollPosition=resultsScroll.getScrollY();lastReport=report;
        deviceList.removeAllViews();lastDevices=new ArrayList<>();
        if(report.isEmpty()){value(deviceList,"Discover devices on your local network. Use Options to adjust the scan.");return lastDevices;}
        try {
            ReportPresentation model=new ReportPresentation(new JSONObject(report));
            TextView summary=value(deviceList,model.summary());summary.setTextSize(17);
            filters();int shown=0;
            for(ReportPresentation.Device device:model.devices) {
                lastDevices.add(device.ip); // Reanalysis retains the entire inventory, independent of the filter.
                if(device.matches(filter)){addDeviceCard(device);shown++;}
            }
            value(deviceList,"Showing "+shown+" of "+model.devices.size()+" devices");
            if(shown==0)value(deviceList,model.devices.isEmpty()?"No devices observed. Review the scan notices.":"No devices match this filter.");
            JSONArray notices=model.json.optJSONArray("identificationNotices");
            if(notices!=null&&notices.length()>0)section(deviceList,"scan-notices","Scan notices ("+notices.length()+")",false,body->{
                for(int i=0;i<notices.length();i++)value(body,notices.optString(i));
            });
            value(deviceList,"Tap a device for details. Full report and JSON export are in Options.");
        } catch(JSONException error){value(deviceList,"Summary unavailable. Open Full report in Options.");}
        resultsScroll.post(()->resultsScroll.scrollTo(0,scrollPosition));return lastDevices;
    }
    private int dp(int value){return Math.round(value*context.getResources().getDisplayMetrics().density);}
    private TextView value(LinearLayout parent,String text) {
        TextView view=new TextView(context);view.setText(text);view.setTextSize(14);
        view.setTextIsSelectable(true);view.setPadding(0,dp(5),0,dp(5));parent.addView(view);return view;
    }
    private void detail(LinearLayout parent,String label,String text){if(!text.isEmpty())value(parent,label+": "+text);}
    private void filters() {
        HorizontalScrollView scroll=new HorizontalScrollView(context);scroll.setHorizontalScrollBarEnabled(false);
        LinearLayout row=new LinearLayout(context);row.setOrientation(LinearLayout.HORIZONTAL);scroll.addView(row);deviceList.addView(scroll);
        for(ReportPresentation.Filter option:ReportPresentation.Filter.values()) {
            Button button=new Button(context);button.setAllCaps(false);button.setText(option.label);
            button.setSelected(filter==option);button.setContentDescription(option.label+(filter==option?", selected":""));
            button.setTextColor(filter==option?Color.BLACK:Color.WHITE);
            button.setBackgroundTintList(android.content.res.ColorStateList.valueOf(filter==option?Color.WHITE:Color.rgb(45,45,45)));
            row.addView(button);button.setOnClickListener(v->{filter=option;render(lastReport);});
        }
    }
    private String ports(SortedSet<Integer> ports) {
        if(ports.isEmpty())return "None observed";
        StringJoiner result=new StringJoiner(", ");int count=0;
        for(int port:ports){if(count++==8)break;result.add(String.valueOf(port));}
        return result+(ports.size()>8?" (+"+(ports.size()-8)+" more)":"");
    }
    private void addDeviceCard(ReportPresentation.Device device) {
        LinearLayout card=new LinearLayout(context);card.setOrientation(LinearLayout.VERTICAL);
        android.graphics.drawable.GradientDrawable shape=new android.graphics.drawable.GradientDrawable();
        shape.setColor(Color.rgb(20,20,20));shape.setCornerRadius(dp(12));shape.setStroke(dp(1),Color.rgb(55,55,55));card.setBackground(shape);
        LinearLayout.LayoutParams margin=new LinearLayout.LayoutParams(-1,-2);margin.setMargins(0,dp(10),0,0);deviceList.addView(card,margin);
        String name=device.name.replaceAll("\\s+"," ").trim();if(name.length()>64)name=name.substring(0,61)+"…";
        String summary=device.ip+(name.isEmpty()?"":" · "+name)+"\nProbable type: "+device.json.optString("probableType","Unknown")
            +"\nOpen TCP ports: "+ports(device.ports)+"\nNmap: "+device.serviceStatus.label+"\nVulnerabilities: "+device.vulnerabilitySummary();
        Button toggle=new Button(context);toggle.setAllCaps(false);toggle.setTextSize(15);
        toggle.setGravity(android.view.Gravity.START|android.view.Gravity.CENTER_VERTICAL);toggle.setPadding(dp(14),dp(10),dp(14),dp(10));card.addView(toggle,new LinearLayout.LayoutParams(-1,-2));
        LinearLayout details=new LinearLayout(context);details.setOrientation(LinearLayout.VERTICAL);details.setPadding(dp(14),0,dp(14),dp(14));card.addView(details);
        boolean expanded=expandedDevices.contains(device.ip);
        if(expanded)populate(details,device);details.setVisibility(expanded?View.VISIBLE:View.GONE);expansionLabel(toggle,summary,expanded);
        toggle.setOnClickListener(v->{
            boolean show=details.getVisibility()!=View.VISIBLE;
            if(show&&details.getChildCount()==0)populate(details,device);
            details.setVisibility(show?View.VISIBLE:View.GONE);
            if(show)expandedDevices.add(device.ip);else expandedDevices.remove(device.ip);
            expansionLabel(toggle,summary,show);
        });
    }
    private void expansionLabel(Button button,String summary,boolean expanded) {
        button.setText(summary+"\n"+(expanded?"▾ Hide details":"▸ Show details"));
        button.setContentDescription(summary+". "+(expanded?"Collapse":"Expand")+" device details.");
    }
    private void section(LinearLayout parent,String key,String title,boolean initiallyOpen,java.util.function.Consumer<LinearLayout> populate) {
        Button toggle=new Button(context);toggle.setAllCaps(false);toggle.setTextSize(14);toggle.setGravity(android.view.Gravity.START|android.view.Gravity.CENTER_VERTICAL);parent.addView(toggle,new LinearLayout.LayoutParams(-1,-2));
        LinearLayout body=new LinearLayout(context);body.setOrientation(LinearLayout.VERTICAL);parent.addView(body);
        boolean open=sectionStates.getOrDefault(key,initiallyOpen);if(open)populate.accept(body);body.setVisibility(open?View.VISIBLE:View.GONE);expansionLabel(toggle,title,open);
        toggle.setOnClickListener(v->{boolean show=body.getVisibility()!=View.VISIBLE;if(show&&body.getChildCount()==0)populate.accept(body);body.setVisibility(show?View.VISIBLE:View.GONE);sectionStates.put(key,show);expansionLabel(toggle,title,show);});
    }
    private void populate(LinearLayout parent,ReportPresentation.Device device) {
        String prefix=device.ip+":";
        section(parent,prefix+"identity","Identification",false,body->{
            String[] fields={"reportedName","dnsHostname","reportedManufacturer","reportedModel","probableType","identityConfidence","suggestedManufacturer","modelConfidence","manufacturerConfidence","typeConfidence","identificationStatus","probeCoverage"};
            for(String field:fields)detail(body,ReportPresentation.label(field),device.json.optString(field));
            JSONArray macs=device.json.optJSONArray("macAddresses");
            if(macs!=null&&macs.length()>0)for(int i=0;i<macs.length();i++){JSONObject mac=macs.optJSONObject(i);if(mac!=null)detail(body,"MAC",mac.optString("address")+" · "+mac.optString("source")+" · "+mac.optString("kind"));}
            else {
                List<DeviceEvidence.Observation> legacy=new ArrayList<>();
                for(JSONObject item:device.evidence)legacy.add(new DeviceEvidence.Observation(item.optString("source"),item.optString("field"),item.optString("value")));
                List<DeviceEvidence.Observation> observed=MacAddresses.observations(legacy);
                if(observed.isEmpty())detail(body,"MAC","Unavailable — not observed or access restricted");
                else for(DeviceEvidence.Observation mac:observed)detail(body,"MAC",mac.value+" · "+mac.source+" · "+MacAddresses.kind(mac.value));
            }
            JSONArray reasons=device.json.optJSONArray("identificationReasons");
            if(reasons!=null)for(int i=0;i<reasons.length();i++)detail(body,"Evidence",reasons.optString(i));
            value(body,"Names and models are reported metadata. Probable type and suggested manufacturer are inferred.");
        });
        section(parent,prefix+"ports","Ports and services ("+device.ports.size()+")",true,body->portTable(body,device));
        section(parent,prefix+"findings","Vulnerabilities and alerts",true,body->{
            detail(body,"Analysis",device.vulnerabilitySummary());
            if(device.findings.isEmpty())value(body,device.vulnerabilityStatus==ReportPresentation.Status.COMPLETED?"No script findings reported. This does not prove absence of vulnerabilities.":"No vulnerability assessment completed for this device.");
            int index=0;
            for(ReportPresentation.Finding finding:device.findings) {
                section(body,prefix+"finding:"+(index++),finding.title+" · "+finding.scope+"\n"+finding.assessment,false,evidence->{
                    detail(evidence,"Affected scope",finding.scope);detail(evidence,"Evidence",finding.evidence);detail(evidence,"Suggested action",finding.action);
                });
            }
            JSONArray analysis=device.json.optJSONArray("analysisFindings");
            if(analysis!=null)section(body,prefix+"observations","Protocol observations",false,observations->{for(int i=0;i<analysis.length();i++)value(observations,analysis.optString(i));});
        });
        section(parent,prefix+"diagnostics","Nmap diagnostics",device.hasFailures(),body->{
            diagnostic(body,"Service detection",device.serviceStatus,device.serviceMessage,device.serviceOutput);
            diagnostic(body,"Vulnerability detection",device.vulnerabilityStatus,device.vulnerabilityMessage,device.vulnerabilityOutput);
            section(body,prefix+"nmap-metadata","Nmap evidence details",false,metadata->{
                for(JSONObject item:device.evidence) {
                    String field=item.optString("field"),source=item.optString("source");
                    if(!source.startsWith("Nmap")||field.equals("outputFile")||field.equals("scanStatus"))continue;
                    detail(metadata,source+" · "+ReportPresentation.label(field),item.optString("value"));
                }
            });
        });
        section(parent,prefix+"metadata","Additional evidence and network metadata",false,body->{
            for(JSONObject item:device.evidence) {
                String field=item.optString("field");if(field.equals("outputFile")||item.optString("source").startsWith("Nmap"))continue;
                detail(body,item.optString("source")+" · "+ReportPresentation.label(field),item.optString("value"));
            }
        });
    }
    private void portTable(LinearLayout body,ReportPresentation.Device device) {
        if(device.ports.isEmpty()){value(body,"No open TCP ports observed.");return;}
        TableLayout table=new TableLayout(context);table.setStretchAllColumns(true);table.setShrinkAllColumns(true);body.addView(table,new LinearLayout.LayoutParams(-1,-2));
        tableRow(table,true,"Port","Service detected","Version / product");
        for(int port:device.ports)tableRow(table,false,port+"/TCP",device.services.getOrDefault(port,"Not identified"),device.versions.getOrDefault(port,"Not identified"));
        value(body,"Only successful TCP connections or Nmap-confirmed open ports appear here.");
    }
    private void tableRow(TableLayout table,boolean header,String... values) {
        TableRow row=new TableRow(context);if(header)row.setBackgroundColor(Color.rgb(45,45,45));
        for(String text:values){TextView cell=new TextView(context);cell.setText(text);cell.setTextSize(13);cell.setPadding(dp(5),dp(8),dp(5),dp(8));cell.setTextIsSelectable(true);if(header)cell.setTypeface(null,android.graphics.Typeface.BOLD);row.addView(cell);}
        table.addView(row);
    }
    private void diagnostic(LinearLayout body,String profile,ReportPresentation.Status status,String message,String reference) {
        detail(body,profile,status.label);
        if(status==ReportPresentation.Status.FAILED)value(body,ReportPresentation.friendlyError(message));
        if(status==ReportPresentation.Status.CANCELLED)value(body,"The analysis was cancelled; results may be incomplete.");
        if(status==ReportPresentation.Status.NOT_RUN)value(body,"No execution recorded for this profile. It may be disabled, waiting, or have no eligible open ports.");
        if(!reference.isEmpty()) {
            Button log=new Button(context);log.setAllCaps(false);log.setText("View full technical log · "+profile);body.addView(log,new LinearLayout.LayoutParams(-1,-2));log.setOnClickListener(v->openNmapOutput.accept(reference));
        } else if(!message.isEmpty())detail(body,"Execution details",message);
    }
}
