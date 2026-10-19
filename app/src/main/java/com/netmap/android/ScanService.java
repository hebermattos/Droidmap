package com.netmap.android;

import android.app.*;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.Uri;
import android.os.*;
import org.json.JSONObject;
import java.io.File;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** User-started, non-exported service. Owns scanning, cancellation and durable results. */
public final class ScanService extends Service {
    static final String START="com.netmap.android.START_SCAN", CANCEL="com.netmap.android.CANCEL_SCAN";
    private static final String CHANNEL="network_scans";
    private static final int NOTIFICATION=42;
    private static volatile ScanSnapshot latest;
    static ScanSnapshot snapshot() { return latest; }
    private final Handler main=new Handler(Looper.getMainLooper());
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private TcpScanner scanner;
    private DeviceIdentifier identifier;
    private NsdDiscovery discovery;
    private LatestScanStore store;
    private volatile boolean destroyed;
    private boolean finishing;
    private long runId;
    private String networkScope;
    private boolean identificationPartial;
    private boolean nmapEnabled;
    private boolean nucleiEnabled;
    private boolean portsOnly;
    private String tool="discovery";
    private String selectedIp;
    private int selectedPort;
    private String nmapArgs="";
    private int nmapVersionIntensity=NmapCommands.DEFAULT_VERSION_INTENSITY;
    private long lastNotification;
    private int acceptedPreview;
    private final AtomicInteger previewVersion=new AtomicInteger();
    private final AtomicLong lastPreview=new AtomicLong();

    @Override public void onCreate() {
        super.onCreate(); store=new LatestScanStore(new File(getFilesDir(),"latest-scan.json"));
        NotificationChannel channel=new NotificationChannel(CHANNEL,"Network scans",NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Scan progress, cancellation and completed results"); channel.setShowBadge(false);
        getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }
    @Override public android.os.IBinder onBind(Intent intent) { return null; }
    @Override public int onStartCommand(Intent intent,int flags,int startId) {
        if(intent==null) { stopSelf(); return START_NOT_STICKY; }
        if(CANCEL.equals(intent.getAction())) {
            if(scanner!=null && intent.getLongExtra("runId",-1)==runId && !finishing) cancel();
            else if(scanner==null) stopSelf();
            return START_NOT_STICKY;
        }
        if(!START.equals(intent.getAction())) { if(scanner==null) stopSelf(); return START_NOT_STICKY; }
        if(scanner!=null) return START_NOT_STICKY; // never queue a duplicate scan
        String target=intent.getStringExtra("target");
        final ScanPlan plan;
        final WifiIpv6Scope wifi;
        try {
            nmapVersionIntensity=NmapCommands.bounded(intent.getIntExtra("nmapVersionIntensity",
                    NmapCommands.DEFAULT_VERSION_INTENSITY),0,9,"Nmap version intensity");
            if(target==null) throw new IllegalArgumentException("Missing scan target");
            ScanPlan requested=new ScanPlan(target,intent.getStringExtra("ports"),intent.getIntExtra("timeout",200),
                intent.getBooleanExtra("complete",false)?ScanPlan.Mode.COMPLETE:ScanPlan.Mode.FAST,intent.getBooleanExtra("adaptive",true));
            wifi=WifiIpv6Scope.capture(this,requested);
            String host=requested.hosts.get(0);
            if(ScanPlan.isIpv6(host)) {
                String normalized=wifi.normalize(host);
                if(normalized==null) throw new IllegalArgumentException("IPv6 target must belong to the connected Wi-Fi network and use its interface scope.");
                plan=new ScanPlan(normalized,intent.getStringExtra("ports"),requested.timeoutMs,requested.mode,requested.adaptive);
            } else plan=requested;
        } catch(RuntimeException e) { failStartup(target,e); return START_NOT_STICKY; }
        tool=intent.getStringExtra("tool"); if(tool==null)tool="discovery";
        selectedIp=intent.getStringExtra("selectedIp");
        selectedPort=intent.getIntExtra("selectedPort",0);
        networkScope=NetworkScope.current(this,plan); identificationPartial=false; portsOnly=intent.getBooleanExtra("portsOnly",false); nmapEnabled=!portsOnly && intent.getBooleanExtra("nmap",true); nucleiEnabled=!portsOnly && intent.getBooleanExtra("nuclei",false); nmapArgs=intent.getStringExtra("nmapArgs"); if(nmapArgs==null)nmapArgs="";
        runId=System.currentTimeMillis(); finishing=false; acceptedPreview=0; previewVersion.set(0); lastPreview.set(0);
        latest=new ScanSnapshot(runId,true,true,0,plan.hosts.size()*plan.ports.size(),target,"Starting scan…","","");
        try {
            Notification notification=notification(latest);
            if(Build.VERSION.SDK_INT>=29) startForeground(NOTIFICATION,notification,ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
            else startForeground(NOTIFICATION,notification);
            scanner=new TcpScanner();
            if ("nmap".equals(tool) || "nuclei".equals(tool)) {
                TcpScanner controller=scanner;
                worker.execute(() -> analyzeDiscovery(plan,target,runId,controller));
                return START_NOT_STICKY;
            }
            DeviceEvidence evidence=new DeviceEvidence(plan.hosts,host -> plan.hosts.size()>1 && wifi.accepts(host));
            identifier=new DeviceIdentifier(plan,evidence); identifier.setHostnameLookup(WifiReverseDns.create(this,plan,evidence));
            if(!portsOnly) identifier.startDiscovery();
            discovery=new NsdDiscovery(this,evidence,plan.mode,wifi);
            if(!portsOnly) discovery.start();
            TcpScanner tcp=scanner; DeviceIdentifier identity=identifier; NsdDiscovery nsd=discovery;
            long started=runId;
            worker.execute(() -> scan(plan,target,started,tcp,identity,nsd,evidence,wifi));
        } catch(RuntimeException e) { failStartup(target,e); }
        return START_NOT_STICKY;
    }
    private void failStartup(String target,RuntimeException error) {
        cleanup(); latest=new ScanSnapshot(runId,false,false,0,0,target==null?"":target,"Unable to start scan: "+error.getMessage(),"","");
        worker.execute(() -> {try {store.save(latest);}catch(Exception ignored){}});
        stopForeground(STOP_FOREGROUND_REMOVE); stopSelf();
    }
    private void scan(ScanPlan plan,String target,long started,TcpScanner tcp,DeviceIdentifier identity,NsdDiscovery nsd,DeviceEvidence evidence,WifiIpv6Scope wifi) {
        try {
            // Write the interruption marker before any network checks.
            store.save(latest);
            if(!portsOnly) identity.addNotices(Ipv6NeighborDiscovery.collect(wifi,evidence,tcp::isCancelled));
            main.post(() -> {
                if (!destroyed && scanner == tcp && !tcp.isCancelled())
                    publish("Discovering active IPs…", 0, true);
            });
            Set<String> liveHosts = HostDiscovery.discover(plan, tcp::isCancelled, count -> {
                if (count == plan.hosts.size() || count % 16 == 0) main.post(() -> {
                    if (!destroyed && scanner == tcp && !tcp.isCancelled())
                        publish("Discovering IPs: " + count + " / " + plan.hosts.size(), 0, true);
                });
            });
            // Even cancellation during host discovery must reach report finalization.
            // TcpScanner returns an empty result when already cancelled.
            Set<String> observedHosts = new HashSet<>(liveHosts);
            observedHosts.addAll(evidence.snapshot().keySet());
            main.post(() -> {
                if (!destroyed && scanner == tcp && !tcp.isCancelled())
                    publish("Scanning TCP ports • " + observedHosts.size() + " responsive IPs prioritized", 0, true);
            });
            AtomicInteger completed=new AtomicInteger(); AtomicLong lastUpdate=new AtomicLong();
            Queue<TcpScanner.Result> liveChecks=new ConcurrentLinkedQueue<>();
            Set<String> liveResponders=ConcurrentHashMap.newKeySet();
            identity.setProgressListener(host -> preview(target,tcp,evidence,liveChecks,identity.endpointChecks(),false));
            List<TcpScanner.Result> results=tcp.scan(plan,(result,count,total) -> {
                if(result.state==TcpScanner.State.OPEN
                        || result.state==TcpScanner.State.CLOSED && liveResponders.add(result.host)) liveChecks.add(result);
                preview(target,tcp,evidence,liveChecks,Collections.emptyList(),false);
                completed.accumulateAndGet(count,Math::max); long now=SystemClock.elapsedRealtime(),previous=lastUpdate.get();
                if(now-previous>=250 && lastUpdate.compareAndSet(previous,now)) main.post(() -> {
                    if(destroyed || scanner!=tcp || tcp.isCancelled() || finishing) return;
                    publish("Checked "+completed.get()+" / "+total+" TCP connections",completed.get(),true);
                });
            }, observedHosts);
            List<TcpScanner.Result> evidenceChecks = results instanceof PackedScanResults
                    ? ((PackedScanResults)results).evidenceChecks() : results;
            if (!portsOnly && !tcp.isCancelled() && wifi.links != null) {
                identity.addNotices(Ipv4MacDiscovery.collect(wifi.links.getInterfaceName(),
                        host -> wifi.links.getLinkAddresses().stream()
                                .anyMatch(local -> WifiReverseDns.inSubnet(local, host)),
                        evidence, tcp::isCancelled, android.os.Build.VERSION.SDK_INT < 29));
            }
            preview(target,tcp,evidence,liveChecks,Collections.emptyList(),true);
            if(!portsOnly) main.post(() -> {if(!destroyed && scanner==tcp && !tcp.isCancelled()) publish("Identifying devices…",results.size(),true);});
            if(!portsOnly && !tcp.isCancelled()) nsd.awaitCompletion(tcp::isCancelled);
            List<String> nmapNotices=Collections.emptyList();
            if(!portsOnly && !tcp.isCancelled()) {
                identity.identify(evidenceChecks);
                if(nmapEnabled&&!tcp.isCancelled()) {
                    List<TcpScanner.Result> observedChecks=new ArrayList<>(evidenceChecks);
                    observedChecks.addAll(identity.endpointChecks());
                    lastPreview.set(0);
                    main.post(()->{if(!destroyed&&scanner==tcp&&!tcp.isCancelled())publish("Running Nmap…",results.size(),true);});
                    nmapNotices=NmapEnricher.enrich(this,plan,observedChecks,evidence,nmapArgs,nmapVersionIntensity,tcp::isCancelled,
                            ()->preview(target,tcp,evidence,liveChecks,identity.endpointChecks(),false));
                }
            }
            List<String> enrichmentNotices=new ArrayList<>(nmapNotices);
            if(nucleiEnabled && !tcp.isCancelled()) {
                main.post(()->{if(!destroyed&&scanner==tcp&&!tcp.isCancelled())publish("Running Nuclei…",results.size(),true);});
                enrichmentNotices.addAll(NucleiEnricher.enrich(this,evidence,NmapTargets.collect(evidenceChecks,evidence),tcp::isCancelled,
                        message->main.post(()->{if(!destroyed && scanner==tcp && !tcp.isCancelled())
                            publish(message,results.size(),true);})));
                preview(target,tcp,evidence,liveChecks,identity.endpointChecks(),false);
            }
            main.post(() -> {
                if(destroyed || scanner!=tcp) return;
                nsd.stop(); finishing=true;
                Map<String,List<DeviceEvidence.Observation>> identified=evidence.snapshot();
                for(TcpScanner.Result check:evidenceChecks) if(check.state==TcpScanner.State.OPEN || check.state==TcpScanner.State.CLOSED) identified.computeIfAbsent(check.host,k->new ArrayList<>());
                List<String> notices=identity.notices(); notices.addAll(enrichmentNotices); notices.addAll(nsd.notices());
                if(evidence.isDiscoveryLimited()) notices.add("IPv6 address discovery limit reached; evidence is partial.");
                if(identity.isTimedOut()) notices.add("Identification time budget reached; evidence is partial.");
                identificationPartial=identity.isPartial() || nsd.isPartial() || evidence.isDiscoveryLimited();
                boolean cancelled=tcp.isCancelled(); publish("Saving results…",results.size(),false);
                worker.execute(() -> saveReport(plan,target,started,results,identity.endpointChecks(),identified,notices,cancelled));
            });
        } catch(Exception e) { finishError(e); }
    }

    /** Uses the completed Discovery snapshot instead of rescanning the network. */
    private void analyzeDiscovery(ScanPlan plan,String target,long started,TcpScanner controller) {
        try {
            ScanSnapshot saved=new LatestScanStore(new File(getFilesDir(),"discovery-scan.json")).load();
            if(saved==null || saved.report.isEmpty()) throw new IllegalStateException("Run Discovery first.");
            JSONObject data=new JSONObject(saved.report);
            if(!"discovery".equals(data.optString("tool"))
                    || data.optBoolean("cancelled",true)
                    || !data.optBoolean("tcpScanComplete",false)
                    || !target.equals(data.optString("target"))
                    || !networkScope.equals(data.optString("networkScope")))
                throw new IllegalStateException("Run Discovery again for this target and Wi-Fi network.");
            List<TcpScanner.Result> open=new ArrayList<>();
            for(String field:new String[]{"checks","advertisedEndpointChecks"}) {
                org.json.JSONArray items=data.optJSONArray(field);
                if(items==null) continue;
                for(int i=0;i<items.length();i++) {
                    JSONObject check=items.optJSONObject(i);
                    if(check==null || !"OPEN".equals(check.optString("state")))continue;
                    String host=check.optString("ip"); int port=check.optInt("port");
                    if(plan.hosts.contains(host)&&port>0&&port<=65535
                            && (selectedIp==null || selectedIp.equals(host) && selectedPort==port))
                        open.add(new TcpScanner.Result(host,port,TcpScanner.State.OPEN));
                }
            }
            if(selectedIp!=null && open.isEmpty())
                throw new IllegalStateException("The selected IP and TCP port were not verified open in Discovery.");
            DeviceEvidence evidence=new DeviceEvidence(plan.hosts);
            Set<String> verifiedOpen=new HashSet<>();
            for(TcpScanner.Result item:open)verifiedOpen.add(item.host+":"+item.port);
            Map<String,LinkedHashSet<Integer>> verifiedPorts=NmapTargets.collect(open,evidence);
            org.json.JSONArray devices=data.optJSONArray("devices");
            if(devices!=null)for(int i=0;i<devices.length();i++){
                JSONObject device=devices.optJSONObject(i);
                if(device==null||!plan.hosts.contains(device.optString("ip"))
                        || selectedIp!=null && !selectedIp.equals(device.optString("ip")))continue;
                String host=device.optString("ip");
                org.json.JSONArray observations=device.optJSONArray("evidence");
                if(observations==null)continue;
                for(int j=0;j<observations.length();j++){
                    JSONObject observation=observations.optJSONObject(j);
                    if(observation==null)continue;
                    String source=observation.optString("source");
                    if(source.startsWith("HTTP tcp/")||source.startsWith("HTTPS tcp/")) {
                        try {
                            int port=Integer.parseInt(source.substring(source.indexOf('/')+1));
                            if(!verifiedOpen.contains(host+":"+port))continue;
                        }catch(NumberFormatException error){continue;}
                    }
                    evidence.add(host,source,observation.optString("field"),observation.optString("value"));
                }
            }
            List<String> notices;
            if("nmap".equals(tool)) {
                main.post(()->{if(!destroyed&&scanner==controller)publish("Running Nmap on open ports…",0,true);});
                AtomicInteger steps=new AtomicInteger();
                notices=NmapEnricher.enrich(this,plan,open,evidence,nmapArgs,nmapVersionIntensity,
                        controller::isCancelled,()->{
                            int count=steps.incrementAndGet();
                            main.post(()->{if(!destroyed && scanner==controller && !controller.isCancelled())
                                publish("Nmap analysis step "+count+" • "+verifiedPorts.size()+" hosts",0,true);});
                        });
            } else {
                main.post(()->{if(!destroyed&&scanner==controller)publish("Running Nuclei on open web ports…",0,true);});
                notices=NucleiEnricher.enrich(this,evidence,verifiedPorts,controller::isCancelled,
                        message->main.post(()->{if(!destroyed && scanner==controller && !controller.isCancelled())
                            publish(message,0,true);}));
            }
            org.json.JSONArray updated=new org.json.JSONArray();
            for(Map.Entry<String,List<DeviceEvidence.Observation>> entry:evidence.snapshot().entrySet())
                updated.put(ScanReport.device(entry.getKey(),entry.getValue()));
            data.put("devices",updated);
            org.json.JSONArray messages=data.optJSONArray("identificationNotices");
            if(messages==null) messages=new org.json.JSONArray();
            for(String notice:notices) messages.put(notice);
            data.put("identificationNotices",messages);
            data.put("tool",tool);
            data.put("discoveryReady",true);
            data.put("nmapEnabled","nmap".equals(tool));
            data.put("nucleiEnabled","nuclei".equals(tool));
            data.put("finishedAtEpochMs",System.currentTimeMillis());
            data.put("cancelled",controller.isCancelled());
            ScanSnapshot finished=new ScanSnapshot(started,false,false,open.size(),open.size(),target,
                    controller.isCancelled()?"Analysis cancelled — partial results":tool+" analysis completed",
                    data.toString(2),new ReportPresentation(data).fullText());
            store.save(finished);
            main.post(()->finish(finished));
        }catch(Exception error){finishError(error);}
    }

    private void saveReport(ScanPlan plan,String target,long started,List<TcpScanner.Result> results,List<TcpScanner.Result> extra,
                            Map<String,List<DeviceEvidence.Observation>> identified,List<String> notices,boolean cancelled) {
        try {
            JSONObject parsed=new JSONObject(ScanReport.json(results,plan,target,cancelled,started,identified,notices,extra));
            boolean networkChanged=!networkScope.equals(NetworkScope.current(this,plan));
            boolean partial=ScanReport.completion(parsed,networkScope,networkChanged,identificationPartial,cancelled);
            String changes;
            try {changes=new ScanHistory(new File(getFilesDir(),"scan-history.json")).save(parsed,plan);}
            catch(Exception e) {changes="History unavailable: "+e.getClass().getSimpleName();}
            parsed.put("historyComparison",changes);
            parsed.put("nmapEnabled",nmapEnabled);
            parsed.put("nucleiEnabled",nucleiEnabled);
            parsed.put("portsOnly",portsOnly);
            parsed.put("tool",tool);
            parsed.put("discoveryReady","discovery".equals(tool) && !cancelled && parsed.optBoolean("tcpScanComplete",false) && !networkChanged);
            parsed.put("nmapCustomArgs",nmapArgs);
            parsed.put("nmapVersionIntensity",nmapVersionIntensity);
            String text=new ReportPresentation(parsed).fullText();
            ScanSnapshot result=new ScanSnapshot(started,false,false,results.size(),plan.hosts.size()*plan.ports.size(),target,
                cancelled?"Cancelled — partial results":portsOnly?"IP and port scan completed":partial?"TCP scan completed — identification partial":"Scan completed",parsed.toString(2),text);
            try {
                store.save(result);
                if("discovery".equals(tool) && parsed.optBoolean("discoveryReady",false))
                    new LatestScanStore(new File(getFilesDir(),"discovery-scan.json")).save(result);
            } catch(Exception e) {result=new ScanSnapshot(started,false,false,result.done,result.total,target,result.message+" • Could not save latest report",result.report,result.text);}
            ScanSnapshot complete=result; main.post(() -> finish(complete));
        } catch(Exception e) {finishError(e);}
    }
    private void finishError(Exception error) {
        if(destroyed) return;
        ScanSnapshot previous=latest;
        ScanSnapshot failure=new ScanSnapshot(runId,false,false,previous==null?0:previous.done,previous==null?0:previous.total,
            previous==null?"":previous.target,"Scan failed: "+error.getMessage(),"","");
        try {store.save(failure);}catch(Exception ignored){}
        main.post(() -> finish(failure));
    }
    private void preview(String target,TcpScanner tcp,DeviceEvidence evidence,Queue<TcpScanner.Result> checks,List<TcpScanner.Result> extra,boolean force) {
        if(destroyed || tcp.isCancelled()) return;
        long now=SystemClock.elapsedRealtime(),previous=lastPreview.get();
        if(!force && (now-previous<1000 || !lastPreview.compareAndSet(previous,now))) return;
        if(force) lastPreview.set(now);
        int version=previewVersion.incrementAndGet();
        try {
            String json=ScanReport.preview(target,new ArrayList<>(checks),extra,evidence.snapshot());
            if ("discovery".equals(tool) || "ports".equals(tool))
                json=new JSONObject(json).put("tool",tool).put("portsOnly","ports".equals(tool)).toString();
            final String previewJson=json;
            main.post(() -> {
                if(destroyed || scanner!=tcp || finishing || version<=acceptedPreview) return;
                acceptedPreview=version; ScanSnapshot state=latest;
                latest=new ScanSnapshot(runId,true,state.cancellable,state.done,state.total,state.target,state.message,previewJson,"");
            });
        } catch(Exception ignored) { /* The final full report still validates and reports serialization errors. */ }
    }
    private void publish(String message,int done,boolean cancellable) {
        ScanSnapshot previous=latest;
        latest=new ScanSnapshot(runId,true,cancellable,done,previous.total,previous.target,message,previous.report,previous.text);
        long now=SystemClock.elapsedRealtime();
        if(now-lastNotification>=1000 || !cancellable) {lastNotification=now; notifyState(latest);}
    }
    private void cancel() {
        scanner.cancel(); if(identifier!=null) identifier.cancel(); if(discovery!=null) discovery.stop();
        publish("Cancelling…",latest.done,false);
    }
    private void finish(ScanSnapshot result) {
        if(destroyed) return;
        latest=result; cleanup(); notifyState(result);
        stopForeground(STOP_FOREGROUND_DETACH); stopSelf();
    }
    private void notifyState(ScanSnapshot state) {
        try {getSystemService(NotificationManager.class).notify(NOTIFICATION,notification(state));}
        catch(SecurityException ignored) { /* Permission denial does not cancel a foreground scan. */ }
    }
    private Notification notification(ScanSnapshot state) {
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP|Intent.FLAG_ACTIVITY_SINGLE_TOP),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder builder=new Notification.Builder(this,CHANNEL).setSmallIcon(R.drawable.ic_scan_notification)
            .setContentTitle("Droidmap • "+state.target).setContentText(state.message).setContentIntent(open)
            .setOnlyAlertOnce(true).setOngoing(state.running).setAutoCancel(!state.running).setCategory(Notification.CATEGORY_PROGRESS);
        if(state.running) builder.setProgress(state.total,state.done,state.done==0);
        if(state.running && state.cancellable) {
            Intent cancel=new Intent(this,ScanService.class).setAction(CANCEL).setData(Uri.parse("droidmap://scan/"+state.runId)).putExtra("runId",state.runId);
            PendingIntent action=PendingIntent.getService(this,1,cancel,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
            builder.addAction(new Notification.Action.Builder(android.R.drawable.ic_menu_close_clear_cancel,"Cancel",action).build());
        }
        return builder.build();
    }
    private void cleanup() {
        if(scanner!=null) scanner.cancel(); if(identifier!=null) identifier.cancel(); if(discovery!=null) discovery.stop();
        scanner=null; identifier=null; discovery=null;
    }
    @Override public void onDestroy() {
        destroyed=true;
        if(scanner!=null && latest!=null) latest=new ScanSnapshot(runId,false,false,latest.done,latest.total,latest.target,"Scan interrupted. Start again to rescan.","","");
        cleanup(); worker.shutdownNow(); main.removeCallbacksAndMessages(null); super.onDestroy();
    }
}
