package com.netmap.android;

import android.content.Context;
import android.net.nsd.*;
import android.os.Build;
import android.annotation.TargetApi;
import android.os.Handler;
import android.os.Looper;
import java.net.Inet6Address;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Serial resolution supports Android 8; discovery stops at the selected mode deadline. */
public final class NsdDiscovery {
    private final NsdManager manager;
    private final DeviceEvidence evidence;
    private final WifiIpv6Scope wifi;
    private final List<Runnable> infoStops=new ArrayList<>();
    private int activeInfo;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final List<NsdManager.DiscoveryListener> listeners=new ArrayList<>();
    private final Queue<NsdServiceInfo> pending=new ArrayDeque<>();
    private final Set<String> seen=new HashSet<>();
    private final List<String> notices=new ArrayList<>();
    private final ScanPlan.Mode mode;
    private final java.util.concurrent.CountDownLatch finished=new java.util.concurrent.CountDownLatch(1);
    private final Queue<String> types=new ArrayDeque<>();
    private volatile boolean running;
    private boolean resolving;
    private volatile boolean incomplete;
    public boolean isPartial() { return incomplete || !notices.isEmpty(); }
    private final Runnable rotate=()-> { for(NsdManager.DiscoveryListener listener:new ArrayList<>(listeners)) stopOne(listener); };
    private final Runnable deadline=this::stop;
    public NsdDiscovery(Context context,DeviceEvidence evidence,ScanPlan.Mode mode,WifiIpv6Scope wifi) {
        this.wifi=wifi;
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
                    if(!running || seen.size()>=128 || !seen.add(info.getServiceType()+"/"+info.getServiceName()+"/"+(Build.VERSION.SDK_INT>=33?info.getNetwork():""))) return;
                    if(Build.VERSION.SDK_INT>=34) trackInfo(info);
                    else {pending.add(info);resolveNext();}
                }); }
                public void onServiceLost(NsdServiceInfo info) { }
                public void onDiscoveryStopped(String type) { handler.post(()-> {listeners.remove(this);discoverNext();}); }
                public void onStartDiscoveryFailed(String type,int code) { handler.post(() -> { if(running && notices.size()<4) notices.add("mDNS " + type + " unavailable ("+code+")"); listeners.remove(this);discoverNext(); }); }
                public void onStopDiscoveryFailed(String type,int code) { }
            };
            listeners.add(listener);
            try {
                if(Build.VERSION.SDK_INT>=33&&wifi.network!=null)
                    manager.discoverServices(type,NsdManager.PROTOCOL_DNS_SD,wifi.network,command->handler.post(command),listener);
                else manager.discoverServices(type,NsdManager.PROTOCOL_DNS_SD,listener);
            }
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
                recordService(service,service.getHost()==null?Collections.emptyList():Collections.singletonList(service.getHost()));
                resolveNext();
            }); }
        }); } catch(RuntimeException e) { resolving=false; handler.post(this::resolveNext); }
    }
    @TargetApi(34)
    private void trackInfo(NsdServiceInfo info) {
        if(activeInfo>=32) {
            incomplete=true;
            if(notices.size()<4) notices.add("mDNS service tracking limit reached; evidence is partial.");
            return;
        }
        if(info.getNetwork()!=null&&wifi.network!=null&&!wifi.network.equals(info.getNetwork())) return;
        NsdManager.ServiceInfoCallback callback=new NsdManager.ServiceInfoCallback() {
            public void onServiceUpdated(NsdServiceInfo service) {
                if(running) recordService(service,service.getHostAddresses());
            }
            public void onServiceLost() { }
            public void onServiceInfoCallbackRegistrationFailed(int code) {
                activeInfo--;incomplete=true;
                if(running&&notices.size()<4) notices.add("mDNS service information unavailable ("+code+")");
            }
            public void onServiceInfoCallbackUnregistered() { }
        };
        try {
            manager.registerServiceInfoCallback(info,command->handler.post(command),callback);
            activeInfo++;
            infoStops.add(()-> {try {manager.unregisterServiceInfoCallback(callback);}catch(RuntimeException ignored) {}});
        } catch(RuntimeException e) {
            incomplete=true;
            if(notices.size()<4) notices.add("mDNS service information unavailable");
        }
    }
    private void recordService(NsdServiceInfo service,List<java.net.InetAddress> addresses) {
        if(Build.VERSION.SDK_INT>=33&&service.getNetwork()!=null&&wifi.network!=null&&!wifi.network.equals(service.getNetwork())) return;
        LinkedHashSet<String> accepted=new LinkedHashSet<>();
        for(java.net.InetAddress address:addresses) {
            if(accepted.size()>=16) {incomplete=true;break;}
            String ip=address instanceof Inet6Address?wifi.normalize(address.getHostAddress()):IpAddresses.canonical(address.getHostAddress());
            if(ip!=null&&evidence.allowDiscoveredHost(ip)) accepted.add(ip);
        }
        for(String ip:accepted) {
            evidence.add(ip,"mDNS","serviceName",service.getServiceName());
            evidence.add(ip,"mDNS","serviceType",service.getServiceType());
            evidence.add(ip,"mDNS","serviceAddresses",String.join(", ",accepted));
            if(ScanPlan.isIpv6(ip)) {
                try {evidence.add(ip,"IPv6","addressType",IpAddresses.kind(IpAddresses.literal(ip)));}catch(Exception ignored) { }
                evidence.add(ip,"IPv6","networkInterface",wifi.links.getInterfaceName());
                if(wifi.owns(ip)) evidence.add(ip,"IPv6","addressOrigin","This phone");
            }
            evidence.advertise(ip,"mDNS",service.getServiceType(),service.getPort());
            Map<String,byte[]> attrs=service.getAttributes();
            for(String key:new String[]{"fn","md","model","ty","product","manufacturer","name","note","uuid","deviceid","rp","am","osvers","hwvers","swvers","firmware","serial"}) {
                byte[] value=attrs.get(key);
                if(value!=null&&value.length<=1024) evidence.add(ip,"mDNS TXT",MdnsFields.field(service.getServiceType(),key),new String(value,StandardCharsets.UTF_8));
            }
        }
    }
    private void stopOne(NsdManager.DiscoveryListener listener) { try { manager.stopServiceDiscovery(listener); } catch(RuntimeException ignored) { } }
    public void stop() {
        if(running && (resolving || !pending.isEmpty())) { incomplete=true; if(notices.size()<4) notices.add("mDNS resolution budget reached; evidence is partial."); }
        running=false; handler.removeCallbacks(deadline); handler.removeCallbacks(rotate); pending.clear();types.clear();
        if(manager!=null) for(NsdManager.DiscoveryListener listener:new ArrayList<>(listeners)) stopOne(listener);
        for(Runnable stop:infoStops) stop.run();
        infoStops.clear();finished.countDown();
    }
    public void awaitCompletion(java.util.function.BooleanSupplier cancelled) throws InterruptedException {
        while(!cancelled.getAsBoolean() && !finished.await(100,java.util.concurrent.TimeUnit.MILLISECONDS)) { }
    }
    public List<String> notices() { return new ArrayList<>(notices); }
}
