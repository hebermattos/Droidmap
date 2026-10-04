package com.netmap.android;

import android.content.Context;
import android.net.nsd.*;
import android.os.Handler;
import android.os.Looper;
import java.net.Inet4Address;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Serial resolution supports Android 8; discovery stops at the selected mode deadline. */
public final class NsdDiscovery {
    private final NsdManager manager;
    private final DeviceEvidence evidence;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final List<NsdManager.DiscoveryListener> listeners=new ArrayList<>();
    private final Queue<NsdServiceInfo> pending=new ArrayDeque<>();
    private final Set<String> seen=new HashSet<>();
    private final List<String> notices=new ArrayList<>();
    private final ScanPlan.Mode mode;
    private final java.util.concurrent.CountDownLatch finished=new java.util.concurrent.CountDownLatch(1);
    private final Queue<String> types=new ArrayDeque<>();
    private boolean running, resolving;
    private volatile boolean incomplete;
    public boolean isPartial() { return incomplete || !notices.isEmpty(); }
    private final Runnable rotate=()-> { for(NsdManager.DiscoveryListener listener:new ArrayList<>(listeners)) stopOne(listener); };
    private final Runnable deadline=this::stop;
    public NsdDiscovery(Context context,DeviceEvidence evidence,ScanPlan.Mode mode) {
        manager=(NsdManager)context.getSystemService(Context.NSD_SERVICE); this.evidence=evidence; this.mode=mode;
    }
    public void start() {
        running=true;
        if(manager==null) { notices.add("mDNS discovery unavailable"); running=false; finished.countDown(); return; }
        handler.postDelayed(deadline,mode.discoverySeconds*1000L);
        types.addAll(Arrays.asList("_http._tcp.","_https._tcp.","_googlecast._tcp.","_airplay._tcp.","_raop._tcp.","_ipp._tcp.","_ipps._tcp.","_printer._tcp.","_smb._tcp.","_workstation._tcp.","_androidtvremote2._tcp.","_adb-tls-connect._tcp.","_hap._tcp.","_spotify-connect._tcp.","_daap._tcp.","_mqtt._tcp.","_rfb._tcp.","_scanner._tcp.","_rtsp._tcp."));
        int batches=(types.size()+5)/6;
        for(int i=0;i<6;i++) discoverNext();
        for(int batch=1;batch<batches;batch++) handler.postDelayed(rotate,mode.discoverySeconds*1000L*batch/batches);
    }
    private void discoverNext() {
        if(!running || types.isEmpty()) return;
        String type=types.remove();
            NsdManager.DiscoveryListener listener=new NsdManager.DiscoveryListener() {
                public void onDiscoveryStarted(String type) { handler.post(() -> { if(!running) stopOne(this); }); }
                public void onServiceFound(NsdServiceInfo info) { handler.post(() -> {
                    if(!running || seen.size()>=128 || !seen.add(info.getServiceType()+"/"+info.getServiceName())) return;
                    pending.add(info); resolveNext();
                }); }
                public void onServiceLost(NsdServiceInfo info) { }
                public void onDiscoveryStopped(String type) { handler.post(()-> {listeners.remove(this);discoverNext();}); }
                public void onStartDiscoveryFailed(String type,int code) { handler.post(() -> { if(running && notices.size()<4) notices.add("mDNS " + type + " unavailable ("+code+")"); listeners.remove(this);discoverNext(); }); }
                public void onStopDiscoveryFailed(String type,int code) { }
            };
            listeners.add(listener);
            try { manager.discoverServices(type,NsdManager.PROTOCOL_DNS_SD,listener); }
            catch(RuntimeException e) { listeners.remove(listener); if(notices.size()<4) notices.add("mDNS " + type + " unavailable"); discoverNext(); }
    }
    private void resolveNext() {
        if(!running || resolving || pending.isEmpty()) return;
        NsdServiceInfo info=pending.remove(); resolving=true;
        try { manager.resolveService(info,new NsdManager.ResolveListener() {
            public void onResolveFailed(NsdServiceInfo service,int code) { handler.post(() -> { resolving=false; resolveNext(); }); }
            public void onServiceResolved(NsdServiceInfo service) { handler.post(() -> {
                resolving=false;
                if(!running) return;
                if(service.getHost() instanceof Inet4Address) {
                    String ip=service.getHost().getHostAddress();
                    evidence.add(ip,"mDNS","serviceName",service.getServiceName());
                    evidence.add(ip,"mDNS","serviceType",service.getServiceType());
                    evidence.advertise(ip,"mDNS",service.getServiceType(),service.getPort());
                    Map<String,byte[]> attrs=service.getAttributes();
                    for(String key:new String[]{"fn","md","model","ty","product","manufacturer","name","note","uuid","deviceid","rp","am","osvers"}) {
                        byte[] value=attrs.get(key);
                        if(value!=null && value.length<=1024) evidence.add(ip,"mDNS TXT",MdnsFields.field(service.getServiceType(),key),new String(value,StandardCharsets.UTF_8));
                    }
                }
                resolveNext();
            }); }
        }); } catch(RuntimeException e) { resolving=false; handler.post(this::resolveNext); }
    }
    private void stopOne(NsdManager.DiscoveryListener listener) { try { manager.stopServiceDiscovery(listener); } catch(RuntimeException ignored) { } }
    public void stop() {
        if(running && (resolving || !pending.isEmpty())) { incomplete=true; if(notices.size()<4) notices.add("mDNS resolution budget reached; evidence is partial."); }
        running=false; finished.countDown(); handler.removeCallbacks(deadline); handler.removeCallbacks(rotate); pending.clear();types.clear();
        if(manager!=null) for(NsdManager.DiscoveryListener listener:new ArrayList<>(listeners)) stopOne(listener);
    }
    public void awaitCompletion(java.util.function.BooleanSupplier cancelled) throws InterruptedException {
        while(!cancelled.getAsBoolean() && !finished.await(100,java.util.concurrent.TimeUnit.MILLISECONDS)) { }
    }
    public List<String> notices() { return new ArrayList<>(notices); }
}
