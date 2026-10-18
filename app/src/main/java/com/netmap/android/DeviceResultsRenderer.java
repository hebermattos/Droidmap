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
    private final java.util.function.BiConsumer<String, Integer> runNmapPort;
    private final java.util.function.BiConsumer<String, Integer> runNucleiPort;
    private ReportPresentation.Filter filter=ReportPresentation.Filter.ALL;
    private String lastReport="";
    private List<String> lastDevices=new ArrayList<>();

    DeviceResultsRenderer(Context context,LinearLayout deviceList,ScrollView resultsScroll,
            Set<String> expandedDevices,java.util.function.Consumer<String> openNmapOutput,
            java.util.function.BiConsumer<String, Integer> runNmapPort,
            java.util.function.BiConsumer<String, Integer> runNucleiPort) {
        this.context=context;this.deviceList=deviceList;this.resultsScroll=resultsScroll;
        this.expandedDevices=expandedDevices;this.openNmapOutput=openNmapOutput;
        this.runNmapPort=runNmapPort;this.runNucleiPort=runNucleiPort;
    }
    List<String> render(String report) {
        int scrollPosition=resultsScroll.getScrollY();lastReport=report;
        deviceList.removeAllViews();lastDevices=new ArrayList<>();
        if(report.isEmpty()){value(deviceList,"Discover devices on your local network. Use Options to adjust the scan.");return lastDevices;}
        try {
            ReportPresentation model=new ReportPresentation(new JSONObject(report));
            if (model.json.optBoolean("portsOnly", false)
                    || "discovery".equals(model.json.optString("tool"))) {
                simplePortsTable(model);
                resultsScroll.post(() -> resultsScroll.scrollTo(0, scrollPosition));
                return lastDevices;
            }
            overview(model);
            vulnerabilityOverview(model);
            filters();int shown=0;
            for(ReportPresentation.Device device:model.devices) {
                lastDevices.add(device.ip); // Reanalysis retains the entire inventory, independent of the filter.
                if(device.matches(filter)){addDeviceCard(device);shown++;}
            }
            if(shown<model.devices.size())value(deviceList,"Showing "+shown+" of "+model.devices.size()+" devices");
            if(shown==0)value(deviceList,model.devices.isEmpty()?"No devices observed. Review the scan notices.":"No devices match this filter.");
            JSONArray notices=model.json.optJSONArray("identificationNotices");
            if(notices!=null&&notices.length()>0)section(deviceList,"scan-notices","Scan notices ("+notices.length()+")",false,body->{
                for(int i=0;i<notices.length();i++)value(body,notices.optString(i));
            });
        } catch(JSONException error){value(deviceList,"Summary unavailable. Open Full report in Options.");}
        resultsScroll.post(()->resultsScroll.scrollTo(0,scrollPosition));return lastDevices;
    }
    /** The dedicated quick scan intentionally shows only IP addresses and open TCP ports. */
    private void simplePortsTable(ReportPresentation model) {
        TextView heading=value(deviceList,"IP addresses and open TCP ports");
        heading.setTextSize(18);
        heading.setTypeface(null,android.graphics.Typeface.BOLD);
        LinearLayout table=panel(deviceList);
        int hosts=0, endpoints=0;
        for(ReportPresentation.Device device:model.devices) {
            lastDevices.add(device.ip);
            if(device.ports.isEmpty()) continue;
            hosts++;
            for(int port:device.ports) {
                LinearLayout entry=new LinearLayout(context);
                entry.setOrientation(LinearLayout.VERTICAL);
                entry.setPadding(dp(8),dp(5),dp(8),dp(5));
                value(entry,device.ip+"  •  TCP "+port);
                LinearLayout tools=new LinearLayout(context);
                tools.setOrientation(LinearLayout.HORIZONTAL);
                Button nmap=new Button(context);
                nmap.setText("Nmap");
                nmap.setAllCaps(false);
                nmap.setContentDescription("Run Nmap on "+device.ip+" TCP port "+port);
                nmap.setOnClickListener(v->runNmapPort.accept(device.ip,port));
                tools.addView(nmap,new LinearLayout.LayoutParams(0,-2,1));
                if (hasWebEvidence(device, port)) {
                    Button nuclei=new Button(context);
                    nuclei.setText("Nuclei");
                    nuclei.setAllCaps(false);
                    nuclei.setContentDescription("Run Nuclei on "+device.ip+" TCP port "+port);
                    nuclei.setOnClickListener(v->runNucleiPort.accept(device.ip,port));
                    tools.addView(nuclei,new LinearLayout.LayoutParams(0,-2,1));
                }
                entry.addView(tools);
                table.addView(entry,new LinearLayout.LayoutParams(-1,-2));
                divider(table);
                endpoints++;
            }
        }
        if(endpoints==0)value(table,"No open TCP ports found in the selected scan.");
        value(deviceList,hosts+" IPs • "+endpoints+" open TCP ports");
    }

    /** Nuclei currently bundles HTTP templates, so TCP openness alone is insufficient. */
    private boolean hasWebEvidence(ReportPresentation.Device device, int port) {
        String http="HTTP tcp/"+port;
        String https="HTTPS tcp/"+port;
        for (JSONObject item:device.evidence) {
            String source=item.optString("source");
            String field=item.optString("field");
            if ((source.equals(http)||source.equals(https))
                    && (field.equals("webUrl")||field.equals("server")||field.equals("httpTitle")))
                return true;
        }
        return false;
    }

    private String allPorts(SortedSet<Integer> ports) {
        StringJoiner joined=new StringJoiner(", ");
        for(int port:ports) joined.add(String.valueOf(port));
        return joined.toString();
    }

    private int dp(int value){return Math.round(value*context.getResources().getDisplayMetrics().density);}
    private TextView value(LinearLayout parent,String text) {
        TextView view=new TextView(context);view.setText(text);view.setTextSize(14);
        view.setGravity(android.view.Gravity.START);view.setTextAlignment(View.TEXT_ALIGNMENT_VIEW_START);
        view.setTextColor(Color.WHITE);view.setTextIsSelectable(true);view.setLineSpacing(dp(2),1f);
        view.setPadding(0,dp(4),0,dp(4));parent.addView(view,new LinearLayout.LayoutParams(-1,-2));return view;
    }
    private void detail(LinearLayout parent,String label,String text) {
        if(text.isEmpty())return;
        LinearLayout field=new LinearLayout(context);field.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams margin=new LinearLayout.LayoutParams(-1,-2);margin.setMargins(0,dp(6),0,dp(6));parent.addView(field,margin);
        TextView caption=value(field,label);caption.setTextSize(12);caption.setTextColor(Color.LTGRAY);caption.setPadding(0,0,0,dp(2));
        TextView content=value(field,text);content.setPadding(0,0,0,0);
    }
    private LinearLayout panel(LinearLayout parent) {
        LinearLayout panel=new LinearLayout(context);panel.setOrientation(LinearLayout.VERTICAL);panel.setPadding(dp(12),dp(6),dp(12),dp(6));
        android.graphics.drawable.GradientDrawable shape=new android.graphics.drawable.GradientDrawable();
        shape.setColor(Color.rgb(20,20,20));shape.setCornerRadius(dp(12));shape.setStroke(dp(1),Color.rgb(55,55,55));panel.setBackground(shape);
        LinearLayout.LayoutParams margin=new LinearLayout.LayoutParams(-1,-2);margin.setMargins(0,dp(6),0,0);parent.addView(panel,margin);return panel;
    }
    private LinearLayout expandedBody(LinearLayout parent) {
        LinearLayout body=new LinearLayout(context);body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(12),dp(8),dp(12),dp(8));
        android.graphics.drawable.GradientDrawable background=new android.graphics.drawable.GradientDrawable();
        background.setColor(Color.rgb(48,48,48));background.setCornerRadius(dp(8));
        background.setStroke(dp(1),Color.rgb(80,80,80));body.setBackground(background);
        LinearLayout.LayoutParams margin=new LinearLayout.LayoutParams(-1,-2);margin.setMargins(0,dp(6),0,dp(6));
        parent.addView(body,margin);return body;
    }
    private Button action(LinearLayout parent) {
        Button button=new Button(context);button.setAllCaps(false);button.setTextSize(14);button.setTextColor(Color.WHITE);
        button.setGravity(android.view.Gravity.START|android.view.Gravity.CENTER_VERTICAL);button.setTextAlignment(View.TEXT_ALIGNMENT_VIEW_START);
        button.setMinHeight(dp(48));button.setMinimumHeight(dp(48));button.setMinWidth(0);button.setMinimumWidth(0);button.setPadding(0,dp(8),0,dp(8));
        button.setBackground(new android.graphics.drawable.RippleDrawable(
                android.content.res.ColorStateList.valueOf(Color.rgb(65,65,65)),new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT),null));
        parent.addView(button,new LinearLayout.LayoutParams(-1,-2));return button;
    }
    private void divider(LinearLayout parent) {
        View divider=new View(context);divider.setBackgroundColor(Color.rgb(55,55,55));
        LinearLayout.LayoutParams line=new LinearLayout.LayoutParams(-1,dp(1));line.setMargins(0,dp(8),0,dp(8));parent.addView(divider,line);
    }
    private void overview(ReportPresentation model) {
        LinearLayout card=panel(deviceList);
        TextView state=value(card,model.scanStatus());
        state.setTypeface(null,android.graphics.Typeface.BOLD);
        int ports=0,alerts=0,failures=0;
        for(ReportPresentation.Device device:model.devices) {
            ports+=device.ports.size();
            if(device.hasAlerts())alerts++;
            if(device.hasFailures())failures++;
        }
        value(card,model.devices.size()+" devices · "+ports+" open TCP endpoints"
                +(alerts>0?" · "+alerts+" with alerts":"")
                +(failures>0?" · "+failures+" with failures":""));
        section(card,"overview-details","Scan details",false,body->{
            for(String line:model.scanDetails().split("\n"))value(body,line);
        });
    }

    /** Compact cross-tool alert index; complete evidence lives in each device card. */
    private void vulnerabilityOverview(ReportPresentation model) {
        int count=0;
        for(ReportPresentation.Device device:model.devices)
            for(ReportPresentation.Finding finding:device.findings)
                if(finding.alert)count++;
        if(count==0) {
            boolean assessed=model.devices.stream().anyMatch(device->
                    device.vulnerabilityStatus==ReportPresentation.Status.COMPLETED
                            ||device.nucleiStatus==ReportPresentation.Status.COMPLETED);
            value(deviceList,assessed?"No vulnerability alerts reported; assessment coverage is limited."
                    :"No completed vulnerability assessment recorded.");
            return;
        }
        section(deviceList,"vulnerability-overview","Alerts ("+count+")",true,body->{
            for(ReportPresentation.Device device:model.devices) {
                for(int index=0;index<device.findings.size();index++) {
                    ReportPresentation.Finding finding=device.findings.get(index);
                    if(!finding.alert)continue;
                    final int selected=index;
                    Button link=action(body);
                    link.setText(device.ip+" · "+finding.scope+"\n"+finding.source+" · "+finding.title);
                    link.setContentDescription("Open alert for "+device.ip+": "+finding.title);
                    link.setOnClickListener(v->{
                        expandedDevices.add(device.ip);
                        sectionStates.put(device.ip+":findings",true);
                        sectionStates.put(device.ip+":finding:"+selected,true);
                        filter=ReportPresentation.Filter.ALL;
                        render(lastReport);
                        View card=deviceList.findViewWithTag(device.ip);
                        if(card!=null)resultsScroll.post(()->resultsScroll.smoothScrollTo(0,card.getTop()));
                    });
                }
            }
            value(body,"Reported alerts require verification.");
        });
    }

    private void filters() {
        HorizontalScrollView scroll=new HorizontalScrollView(context);scroll.setHorizontalScrollBarEnabled(false);
        LinearLayout row=new LinearLayout(context);row.setOrientation(LinearLayout.HORIZONTAL);scroll.addView(row);deviceList.addView(scroll);
        for(ReportPresentation.Filter option:ReportPresentation.Filter.values()) {
            Button button=new Button(context);button.setAllCaps(false);button.setText(option.label);button.setTextSize(14);
            button.setMinHeight(dp(48));button.setMinimumHeight(dp(48));button.setMinWidth(0);button.setMinimumWidth(0);button.setPadding(dp(12),dp(8),dp(12),dp(8));
            button.setSelected(filter==option);button.setContentDescription(option.label+(filter==option?", selected":""));
            button.setTextColor(filter==option?Color.BLACK:Color.WHITE);
            android.graphics.drawable.GradientDrawable background=new android.graphics.drawable.GradientDrawable();
            background.setColor(filter==option?Color.WHITE:Color.rgb(45,45,45));background.setCornerRadius(dp(8));
            button.setBackground(new android.graphics.drawable.RippleDrawable(android.content.res.ColorStateList.valueOf(Color.GRAY),background,null));
            LinearLayout.LayoutParams margin=new LinearLayout.LayoutParams(-2,-2);margin.setMargins(0,dp(6),dp(8),dp(6));row.addView(button,margin);button.setOnClickListener(v->{filter=option;render(lastReport);});
        }
    }
    private String ports(SortedSet<Integer> ports) {
        if(ports.isEmpty())return "None observed";
        return allPorts(ports);
    }
    private void addDeviceCard(ReportPresentation.Device device) {
        LinearLayout card=panel(deviceList);
        card.setTag(device.ip);
        Button toggle=action(card);
        toggle.setTypeface(null,android.graphics.Typeface.BOLD);
        toggle.setTextSize(16);
        if(!device.name.isEmpty()) {
            TextView name=value(card,device.name);
            name.setSingleLine(true);
            name.setEllipsize(android.text.TextUtils.TruncateAt.END);
        }
        TextView summary=value(card,"TCP: "+ports(device.ports));
        summary.setTextColor(Color.LTGRAY);
        List<String> attention=new ArrayList<>();
        if(device.hasAlerts())attention.add("Alerts reported");
        if(device.hasFailures())attention.add("Tool failed");
        if(device.serviceStatus==ReportPresentation.Status.RUNNING
                ||device.vulnerabilityStatus==ReportPresentation.Status.RUNNING)attention.add("Nmap running");
        if(device.nucleiStatus==ReportPresentation.Status.RUNNING)attention.add("Nuclei running");
        if(!attention.isEmpty())value(card,String.join(" · ",attention));
        LinearLayout details=expandedBody(card);
        boolean expanded=expandedDevices.contains(device.ip);
        if(expanded)populate(details,device);
        details.setVisibility(expanded?View.VISIBLE:View.GONE);
        deviceToggleLabel(toggle,device.ip,expanded);
        toggle.setOnClickListener(v->{
            boolean show=details.getVisibility()!=View.VISIBLE;
            if(show&&details.getChildCount()==0)populate(details,device);
            details.setVisibility(show?View.VISIBLE:View.GONE);
            if(show)expandedDevices.add(device.ip);else expandedDevices.remove(device.ip);
            deviceToggleLabel(toggle,device.ip,show);
        });
    }

    private void webLink(LinearLayout parent,String url) {
        Button link=action(parent);link.setText(url);
        link.setContentDescription("Open web interface: "+url);
        link.setPaintFlags(link.getPaintFlags()|android.graphics.Paint.UNDERLINE_TEXT_FLAG);
        link.setOnClickListener(view->{
            android.content.Intent intent=new android.content.Intent(android.content.Intent.ACTION_VIEW,android.net.Uri.parse(url));
            if(!(context instanceof android.app.Activity))intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
            try {context.startActivity(intent);}
            catch(android.content.ActivityNotFoundException unavailable) {
                Toast.makeText(context,"No browser available to open this link.",Toast.LENGTH_SHORT).show();
            }
        });
    }
    private void deviceToggleLabel(Button button,String ip,boolean expanded) {
        button.setText((expanded?"▾ ":"▸ ")+ip);
        button.setContentDescription((expanded?"Collapse":"Expand")+" details for "+ip);
    }
    private void sectionLabel(Button button,String title,boolean expanded) {
        button.setText((expanded?"▾ ":"▸ ")+title);
        button.setTypeface(null,android.graphics.Typeface.BOLD);
        button.setContentDescription(title+". "+(expanded?"Collapse":"Expand")+" section.");
    }
    private void section(LinearLayout parent,String key,String title,boolean initiallyOpen,java.util.function.Consumer<LinearLayout> populate) {
        Button toggle=action(parent);
        LinearLayout body=expandedBody(parent);
        boolean open=sectionStates.getOrDefault(key,initiallyOpen);if(open)populate.accept(body);body.setVisibility(open?View.VISIBLE:View.GONE);sectionLabel(toggle,title,open);
        toggle.setOnClickListener(v->{boolean show=body.getVisibility()!=View.VISIBLE;if(show&&body.getChildCount()==0)populate.accept(body);body.setVisibility(show?View.VISIBLE:View.GONE);sectionStates.put(key,show);sectionLabel(toggle,title,show);});
    }
    private void populate(LinearLayout parent,ReportPresentation.Device device) {
        String prefix=device.ip+":";
        SortedSet<String> links=device.webLinks();
        if(!links.isEmpty())section(parent,prefix+"web","Web interfaces ("+links.size()+")",false,body->{
            for(String url:links)webLink(body,url);
        });
        section(parent,prefix+"identity","Identification",false,body->{
            String[] fields={"reportedName","dnsHostname","reportedManufacturer","reportedModel","probableType"};
            Set<String> displayed=new HashSet<>();
            for(String field:fields) {
                String text=device.json.optString(field);
                if(!text.isEmpty()&&displayed.add(text))detail(body,ReportPresentation.label(field),text);
            }
            JSONArray macs=device.json.optJSONArray("macAddresses");
            Set<String> addresses=new LinkedHashSet<>();
            if(macs!=null)for(int i=0;i<macs.length();i++) {
                JSONObject mac=macs.optJSONObject(i);
                if(mac!=null&&!mac.optString("address").isEmpty())addresses.add(mac.optString("address"));
            }
            if(addresses.isEmpty()) {
                List<DeviceEvidence.Observation> legacy=new ArrayList<>();
                for(JSONObject item:device.evidence)legacy.add(new DeviceEvidence.Observation(item.optString("source"),item.optString("field"),item.optString("value")));
                for(DeviceEvidence.Observation mac:MacAddresses.observations(legacy))addresses.add(mac.value);
            }
            for(String address:addresses)detail(body,"MAC",address+" · "+MacAddresses.kind(address));
            section(body,prefix+"identity-details","Confidence and sources",false,more->{
                String[] technical={"identityConfidence","suggestedManufacturer","modelConfidence","manufacturerConfidence","typeConfidence","identificationStatus","probeCoverage"};
                for(String field:technical)detail(more,ReportPresentation.label(field),device.json.optString(field));
                if(macs!=null)for(int i=0;i<macs.length();i++) {
                    JSONObject mac=macs.optJSONObject(i);
                    if(mac!=null)detail(more,"MAC source",mac.optString("address")+" · "+mac.optString("source"));
                }
                JSONArray reasons=device.json.optJSONArray("identificationReasons");
                if(reasons!=null)for(int i=0;i<reasons.length();i++)detail(more,"Evidence",reasons.optString(i));
                for(JSONObject item:device.evidence)if(ReportPresentation.Device.identityEvidence(item))
                    detail(more,item.optString("source")+" · "+ReportPresentation.label(item.optString("field")),item.optString("value"));
                value(more,"Names and models are reported metadata. Type and suggested manufacturer are inferred.");
            });
        });
        section(parent,prefix+"ports","Ports and services ("+device.ports.size()+")",false,body->portList(body,device));
        if(!device.findings.isEmpty()||device.vulnerabilityStatus!=ReportPresentation.Status.NOT_RUN
                ||device.nucleiStatus!=ReportPresentation.Status.NOT_RUN)
            section(parent,prefix+"findings","Findings ("+device.findings.size()+")",false,body->{
                if(device.findings.isEmpty())value(body,device.vulnerabilitySummary());
                int index=0;
                for(ReportPresentation.Finding finding:device.findings) {
                    section(body,prefix+"finding:"+(index++),finding.source+" · "+finding.title+" · "+finding.scope,false,evidence->{
                        detail(evidence,"Assessment",finding.assessment);
                        detail(evidence,"Evidence",finding.evidence);
                        detail(evidence,"Suggested action",finding.action);
                    });
                }
            });
        JSONArray analysis=device.json.optJSONArray("analysisFindings");
        List<String> observations=new ArrayList<>();
        if(analysis!=null)for(int i=0;i<analysis.length();i++) {
            String text=analysis.optString(i);
            if(!text.startsWith("Review:")&&!observations.contains(text))observations.add(text);
        }
        if(!observations.isEmpty())section(parent,prefix+"observations","Protocol observations",false,body->{
            for(String text:observations)value(body,text);
        });
        if(device.nucleiStatus!=ReportPresentation.Status.NOT_RUN)
            section(parent,prefix+"nuclei","Nuclei · "+device.nucleiStatus.label,false,body->{
                for(JSONObject item:device.evidence) {
                    if(!item.optString("source").equals("Nuclei")||!item.optString("field").startsWith("endpoint:"))continue;
                    detail(body,"TCP port "+item.optString("field").substring("endpoint:".length()),item.optString("value"));
                }
                value(body,"Configured templates do not indicate how many individual checks succeeded.");
            });
        if(device.serviceStatus!=ReportPresentation.Status.NOT_RUN||device.vulnerabilityStatus!=ReportPresentation.Status.NOT_RUN)
            section(parent,prefix+"diagnostics","Nmap diagnostics",false,body->{
                if(device.serviceStatus!=ReportPresentation.Status.NOT_RUN)
                    diagnostic(body,"Service detection",device.serviceStatus,device.serviceMessage,device.serviceOutput);
                if(device.vulnerabilityStatus!=ReportPresentation.Status.NOT_RUN)
                    diagnostic(body,"Vulnerability detection",device.vulnerabilityStatus,device.vulnerabilityMessage,device.vulnerabilityOutput);
                // Older reports may lack log files; retain their raw Nmap evidence as a fallback.
                boolean legacy=device.serviceStatus!=ReportPresentation.Status.NOT_RUN&&device.serviceOutput.isEmpty()
                        ||device.vulnerabilityStatus!=ReportPresentation.Status.NOT_RUN&&device.vulnerabilityOutput.isEmpty();
                if(legacy)section(body,prefix+"nmap-metadata","Stored Nmap evidence",false,metadata->{
                    for(JSONObject item:device.evidence) {
                        String field=item.optString("field"),source=item.optString("source");
                        if(!source.startsWith("Nmap")||field.equals("outputFile")||field.equals("scanStatus"))continue;
                        detail(metadata,source+" · "+ReportPresentation.label(field),item.optString("value"));
                    }
                });
            });
        boolean additional=device.evidence.stream().anyMatch(ReportPresentation.Device::additionalEvidence);
        if(additional)section(parent,prefix+"metadata","Additional evidence and network metadata",false,body->{
            for(JSONObject item:device.evidence) {
                String field=item.optString("field");if(!ReportPresentation.Device.additionalEvidence(item))continue;
                detail(body,item.optString("source")+" · "+ReportPresentation.label(field),item.optString("value"));
            }
        });
    }
    private void portList(LinearLayout body,ReportPresentation.Device device) {
        if(device.ports.isEmpty()){value(body,"No open TCP ports observed.");return;}
        for(int port:device.ports)value(body,device.portLine(port));
    }

    private void diagnostic(LinearLayout body,String profile,ReportPresentation.Status status,String message,String reference) {
        detail(body,profile,status.label);
        if(status==ReportPresentation.Status.FAILED)value(body,ReportPresentation.friendlyError(message));
        if(status==ReportPresentation.Status.CANCELLED)value(body,"The analysis was cancelled; results may be incomplete.");
        if(status==ReportPresentation.Status.NOT_RUN)value(body,"No execution recorded for this profile. It may be disabled, waiting, or have no eligible open ports.");
        if(!reference.isEmpty()) {
            Button log=action(body);log.setText("View full log · "+profile);log.setOnClickListener(v->openNmapOutput.accept(reference));
        } else if(!message.isEmpty())detail(body,"Execution details",message);
    }
}


