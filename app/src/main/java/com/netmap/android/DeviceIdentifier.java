package com.netmap.android;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Bounded SSDP, UPnP and service reads. No redirects, authentication or TLS bypass. */
public final class DeviceIdentifier {
    public interface HostnameLookup {
        void lookup(String host, long deadline, java.util.function.BooleanSupplier stopped);
        void cancel();
        default List<String> notices() { return Collections.emptyList(); }
    }
    private volatile HostnameLookup hostnameLookup;
    public void setHostnameLookup(HostnameLookup lookup) { hostnameLookup=lookup; }
    private final DeviceEvidence evidence;
    private final ScanPlan plan;
    private final TcpScanner endpointScanner=new TcpScanner();
    private final TcpScanner.Connector endpointConnector;
    private final List<TcpScanner.Result> endpointChecks=Collections.synchronizedList(new ArrayList<>());
    private Map<String,List<DeviceEvidence.Endpoint>> advertised=Collections.emptyMap();
    private final Map<String,TcpScanner.Result> initialChecks=new HashMap<>();
    public List<TcpScanner.Result> endpointChecks() { synchronized(endpointChecks) { return new ArrayList<>(endpointChecks); } }
    private final Set<String> hosts;
    private final Set<Closeable> active = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private volatile boolean timedOut;
    private volatile long deadline=Long.MAX_VALUE;
    private final List<String> notices = Collections.synchronizedList(new ArrayList<>());
    public DeviceIdentifier(ScanPlan plan,DeviceEvidence evidence) { this(plan,evidence,null); }
    DeviceIdentifier(ScanPlan plan,DeviceEvidence evidence,TcpScanner.Connector endpointConnector) {
        this.plan=plan; this.hosts=new HashSet<>(plan.hosts); this.evidence=evidence;
        this.endpointConnector=endpointConnector==null?endpointScanner::probe:endpointConnector;
    }
    public void cancel() {
        cancelled.set(true); endpointScanner.cancel();
        if(hostnameLookup!=null) hostnameLookup.cancel();
        for (Closeable socket : active) try { socket.close(); } catch (IOException ignored) { }
    }
    public boolean isTimedOut() { return timedOut; }
    public List<String> notices() { synchronized(notices) { List<String> result=new ArrayList<>(notices); if(hostnameLookup!=null) result.addAll(hostnameLookup.notices()); return result; } }
    private boolean stopped() { return cancelled.get() || Thread.currentThread().isInterrupted() || System.nanoTime() >= deadline; }
    public void identify(List<TcpScanner.Result> checks) throws InterruptedException {
        deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(plan.mode.identificationSeconds);
        if (cancelled.get()) return;
        discoverSsdp();
        advertised=evidence.endpoints();
        for(TcpScanner.Result check:checks) initialChecks.put(check.host+":"+check.port,check);
        ExecutorService workers=Executors.newFixedThreadPool(8);
        try {
            Map<String,List<Integer>> open=new LinkedHashMap<>();
            for (TcpScanner.Result check : checks) if (check.state==TcpScanner.State.OPEN) open.computeIfAbsent(check.host,k->new ArrayList<>()).add(check.port);
            for(String host:hosts) open.computeIfAbsent(host,k->new ArrayList<>());
            for (Map.Entry<String,List<Integer>> host : open.entrySet()) workers.submit(() -> fingerprint(host.getKey(),host.getValue()));
            workers.shutdown();
            while (!workers.awaitTermination(100,TimeUnit.MILLISECONDS)) {
                if (stopped()) { timedOut=!cancelled.get() && System.nanoTime()>=deadline; cancel(); workers.shutdownNow(); }
            }
            if(!cancelled.get() && System.nanoTime()>=deadline) timedOut=true;
        } catch (InterruptedException e) { cancel(); throw e;
        } finally { workers.shutdownNow(); cancel(); }
    }
    private void discoverSsdp() {
        Map<String,String> locations=new LinkedHashMap<>();
        try (DatagramSocket socket=new DatagramSocket()) {
            active.add(socket);
            try {
                socket.setSoTimeout(200);
                byte[] request=("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
                socket.send(new DatagramPacket(request,request.length,InetAddress.getByName("239.255.255.250"),1900));
                long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(plan.mode==ScanPlan.Mode.COMPLETE?5:3); int packets=0;
                while (!stopped() && System.nanoTime()<end && packets<512) {
                    byte[] buffer=new byte[8192]; DatagramPacket response=new DatagramPacket(buffer,buffer.length);
                    try { socket.receive(response); } catch(SocketTimeoutException ignored) { continue; }
                    packets++;
                    String ip=response.getAddress().getHostAddress();
                    if (!hosts.contains(ip)) continue;
                    String raw=new String(buffer,0,response.getLength(),StandardCharsets.UTF_8);
                    if (!raw.startsWith("HTTP/1.1 200") && !raw.startsWith("HTTP/1.0 200")) continue;
                    Map<String,String> h=DeviceEvidence.headers(raw);
                    for(String key:new String[]{"server","st","usn"}) evidence.add(ip,"SSDP",key.equals("st")?"serviceType":key,h.get(key));
                    String location=h.get("location");
                    if (allowedLocation(location,ip)) {
                        locations.putIfAbsent(ip,location);
                        try { URI uri=new URI(location); evidence.advertise(ip,"SSDP description","_http._tcp.",uri.getPort()==-1?80:uri.getPort()); } catch(URISyntaxException ignored) { }
                    }
                }
            } finally { active.remove(socket); }
        } catch (IOException | SecurityException e) { if (!cancelled.get()) notices.add("SSDP discovery unavailable: " + e.getClass().getSimpleName()); }
        // Description fetches use the same fixed pool and global budget as fingerprints.
        descriptionLocations=locations;
    }
    private Map<String,String> descriptionLocations=Collections.emptyMap();
    public static boolean allowedLocation(String location,String ip) {
        if (location==null || location.length()>2048) return false;
        try {
            URI uri=new URI(location);
            return "http".equalsIgnoreCase(uri.getScheme()) && ip.equals(uri.getHost()) && uri.getUserInfo()==null && uri.getFragment()==null && (uri.getPort()==-1 || uri.getPort()>0 && uri.getPort()<=65535);
        } catch (URISyntaxException e) { return false; }
    }
    private void fingerprint(String host,List<Integer> ports) {
        if (stopped()) return;
        netbios(host);
        // PTR records may be cached: query only responders or independently announced devices.
        boolean responding=!ports.isEmpty() || evidence.hasObservations(host);
        if(!responding) for(TcpScanner.Result check:initialChecks.values()) {
            if(check.host.equals(host) && check.state==TcpScanner.State.CLOSED) { responding=true; break; }
        }
        if(responding && hostnameLookup!=null && !stopped()) hostnameLookup.lookup(host,deadline,this::stopped);
        String location=descriptionLocations.get(host);
        if (location!=null) description(host,location);
        Map<Integer,String> probes=new LinkedHashMap<>();
        for(DeviceEvidence.Endpoint endpoint:advertised.getOrDefault(host,Collections.emptyList())) {
            if(stopped()) break;
            TcpScanner.Result result=verifyEndpoint(host,endpoint.port);
            if(result==null) break;
            endpointChecks.add(result);
            evidence.add(host,endpoint.source,"endpointCheck","tcp/"+endpoint.port+" "+result.state+" ("+result.attempts+" attempt(s))");
            if(result.state==TcpScanner.State.OPEN) probes.put(endpoint.port,endpoint.serviceType);
        }
        for(int port:ports) probes.putIfAbsent(port,"");
        int reads=0;
        for(Map.Entry<Integer,String> probe:probes.entrySet()) {
            int port=probe.getKey(); String type=probe.getValue();
            if(stopped() || reads>=plan.mode.fingerprintLimit) break;
            if(isIppEndpoint(port,type)) {
                reads++; printer(host,port); continue;
            }
            // An HTTP announcement permits HTTP on a nonstandard port; never infer it for TLS/printing services.
            boolean http=isHttpEndpoint(port,type);
            if(http) {
                reads++;
                String response=read(host,port,"GET / HTTP/1.0\r\nHost: "+host+":"+port+"\r\nUser-Agent: Netmap-Lite/0.4\r\nConnection: close\r\n\r\n",16384);
                if(response.startsWith("HTTP/")) {
                    Map<String,String> h=DeviceEvidence.headers(response);
                    evidence.add(host,"HTTP tcp/"+port,"server",h.get("server"));
                    evidence.add(host,"HTTP tcp/"+port,"httpTitle",DeviceEvidence.title(response));
                }
            } else if(port==21 || port==22 || port==23) {
                reads++; String banner=read(host,port,null,4096);
                String line=banner.split("\\r?\\n",2)[0];
                if(!line.isEmpty()) evidence.add(host,"Banner tcp/"+port,"banner",line);
            }
        }
    }
    static boolean isIppEndpoint(int port,String type) { return type.startsWith("_ipp._tcp") || type.isEmpty() && port==631; }
    static boolean isHttpEndpoint(int port,String type) {
        return type.startsWith("_http._tcp") || type.isEmpty() && (port==80 || port==8000 || port==8080 || port==8888);
    }
    TcpScanner.Result verifyEndpoint(String host,int port) {
        if(!hosts.contains(host) || port<1 || port>65535 || stopped()) return null;
        TcpScanner.Result cached=initialChecks.get(host+":"+port);
        if(cached!=null && cached.state!=TcpScanner.State.NO_RESPONSE) return cached;
        int timeout=plan.timeoutMs,attempts=0; TcpScanner.State state=TcpScanner.State.ERROR;
        for(int retry=0;retry<=plan.mode.retries;retry++) {
            if(stopped()) break;
            int remaining=(int)Math.min(3000,TimeUnit.NANOSECONDS.toMillis(deadline-System.nanoTime()));
            timeout=Math.max(1,Math.min(timeout,remaining)); attempts++;
            state=endpointConnector.connect(host,port,timeout);
            if(state!=TcpScanner.State.NO_RESPONSE || retry==plan.mode.retries) break;
            timeout=plan.mode.nextTimeout(timeout);
        }
        return attempts==0 || cancelled.get()?null:new TcpScanner.Result(host,port,state,attempts,timeout);
    }
    private void netbios(String host) {
        if(stopped()) return;
        int id=java.util.concurrent.ThreadLocalRandom.current().nextInt(65536);
        try(DatagramSocket socket=new DatagramSocket()) {
            active.add(socket);
            try {
                if(stopped()) return;
                socket.connect(InetAddress.getByName(host),137); socket.setSoTimeout(250);
                byte[] request=NetBios.query(id); socket.send(new DatagramPacket(request,request.length));
                byte[] buffer=new byte[4096]; DatagramPacket packet=new DatagramPacket(buffer,buffer.length); socket.receive(packet);
                if(stopped()) return;
                Map<String,String> fields=NetBios.parse(Arrays.copyOf(buffer,packet.getLength()),id);
                for(Map.Entry<String,String> field:fields.entrySet()) evidence.add(host,"NetBIOS node status",field.getKey(),field.getValue());
            } finally { active.remove(socket); }
        } catch(IOException | SecurityException ignored) { }
    }
    private void description(String host,String location) {
        try {
            URI uri=new URI(location); int port=uri.getPort()==-1?80:uri.getPort();
            String path=uri.getRawPath(); if(path==null || path.isEmpty()) path="/";
            if(uri.getRawQuery()!=null) path+="?"+uri.getRawQuery();
            String response=read(host,port,"GET "+path+" HTTP/1.0\r\nHost: "+host+":"+port+"\r\nConnection: close\r\n\r\n",65536);
            if (!response.matches("(?s)HTTP/1\\.[01] 200\\b.*")) return;
            int body=response.indexOf("\r\n\r\n"); if(body<0) return;
            for(Map.Entry<String,String> field:DeviceEvidence.upnpFields(response.substring(body+4)).entrySet()) evidence.add(host,"UPnP description",field.getKey(),field.getValue());
        } catch(URISyntaxException ignored) { }
    }
    private void printer(String host,int port) {
        if(stopped()) return;
        String resource=Ipp.resource(DeviceEvidence.first(evidence.observations(host),"printerResource"));
        if(resource==null) return;
        try {
            byte[] body=Ipp.request("ipp://"+host+":"+port+resource);
            ByteArrayOutputStream request=new ByteArrayOutputStream();
            request.write(("POST "+resource+" HTTP/1.1\r\nHost: "+host+":"+port+"\r\nContent-Type: application/ipp\r\nContent-Length: "+body.length+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII)); request.write(body);
            byte[] response=readBytes(host,port,request.toByteArray(),65536);
            Map<String,String> fields=Ipp.parse(HttpReply.body(response,"application/ipp"));
            if(!fields.isEmpty()) evidence.add(host,"IPP Get-Printer-Attributes","serviceType","_ipp._tcp.");
            fields.forEach((field,value)->evidence.add(host,"IPP Get-Printer-Attributes",field,value));
        } catch(IOException ignored) { }
    }
    String read(String host,int port,String request,int limit) {
        return new String(readBytes(host,port,request==null?null:request.getBytes(StandardCharsets.US_ASCII),limit),StandardCharsets.UTF_8);
    }
    byte[] readBytes(String host,int port,byte[] request,int limit) {
        if(stopped()) return new byte[0];
        try(Socket socket=new Socket()) {
            active.add(socket);
            try {
                if(stopped()) return new byte[0];
                socket.connect(new InetSocketAddress(host,port),500);
                long readDeadline=Math.min(deadline,System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(plan.mode==ScanPlan.Mode.COMPLETE?1800:900));
                if(request!=null) socket.getOutputStream().write(request);
                ByteArrayOutputStream result=new ByteArrayOutputStream(); byte[] buffer=new byte[2048];
                while(!stopped() && result.size()<limit && System.nanoTime()<readDeadline) {
                    socket.setSoTimeout((int)Math.max(1,Math.min(500,TimeUnit.NANOSECONDS.toMillis(readDeadline-System.nanoTime()))));
                    int count;
                    try { count=socket.getInputStream().read(buffer,0,Math.min(buffer.length,limit-result.size())); }
                    catch(SocketTimeoutException e) { break; }
                    if(count<0) break; result.write(buffer,0,count);
                    if(request==null && result.toString("UTF-8").contains("\n")) break;
                }
                return result.toByteArray();
            } finally { active.remove(socket); }
        } catch(IOException | SecurityException e) { return new byte[0]; }
    }
}
