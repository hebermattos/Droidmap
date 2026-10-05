package com.netmap.android;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Bounded SSDP, UPnP and service reads. No redirects, authentication or TLS bypass. */
public final class DeviceIdentifier {
    public interface HostnameLookup {
        void lookup(String host, long deadline, java.util.function.BooleanSupplier stopped);

        void cancel();

        default List<String> notices() {
            return Collections.emptyList();
        }
    }

    private volatile HostnameLookup hostnameLookup;

    public void setHostnameLookup(HostnameLookup lookup) {
        hostnameLookup = lookup;
    }

    private final DeviceEvidence evidence;
    private final ScanPlan plan;
    private final ProbeContext probeContext;
    private final TlsProbe tlsProbe;
    private final RtspProbe rtspProbe;
    private final NetBiosProbe netBiosProbe;
    private final UpnpProbe upnpProbe;
    private final List<DeviceProbe> serviceProbes;
    private final TcpScanner endpointScanner = new TcpScanner();
    private final TcpScanner.Connector endpointConnector;
    private final List<TcpScanner.Result> endpointChecks =
            Collections.synchronizedList(new ArrayList<>());
    private Map<String, List<DeviceEvidence.Endpoint>> advertised = Collections.emptyMap();
    private final Map<String, TcpScanner.Result> initialChecks = new HashMap<>();
    private final Set<String> respondingHosts = new HashSet<>();
    private final Runnable discoveryTask;
    private ExecutorService discoveryWorker;
    private Future<?> discoveryFuture;
    private volatile java.util.function.Consumer<String> progressListener;

    public void setProgressListener(java.util.function.Consumer<String> listener) {
        progressListener = listener;
    }

    public synchronized void startDiscovery() {
        if (discoveryFuture != null || cancelled.get()) return;
        discoveryWorker = Executors.newSingleThreadExecutor();
        ExecutorService executor = discoveryWorker;
        discoveryFuture =
                executor.submit(
                        () -> {
                            try {
                                discoveryTask.run();
                            } finally {
                                executor.shutdown();
                            }
                        });
    }

    boolean awaitDiscovery(long until) throws InterruptedException {
        startDiscovery();
        Future<?> future;
        synchronized (this) {
            future = discoveryFuture;
        }
        if (future == null) return false;
        try {
            future.get(Math.max(1, until - System.nanoTime()), TimeUnit.NANOSECONDS);
            return !cancelled.get();
        } catch (CancellationException e) {
            return false;
        } catch (TimeoutException e) {
            timedOut = true;
            cancel();
            return false;
        } catch (ExecutionException e) {
            failed = true;
            notices.add("SSDP discovery unavailable: " + e.getCause().getClass().getSimpleName());
            return !cancelled.get();
        } catch (InterruptedException e) {
            cancel();
            throw e;
        }
    }

    public List<TcpScanner.Result> endpointChecks() {
        synchronized (endpointChecks) {
            return new ArrayList<>(endpointChecks);
        }
    }

    private final Set<String> hosts;
    private final Set<Closeable> active = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private volatile boolean timedOut;
    private volatile boolean failed;

    public boolean isPartial() {
        return timedOut || failed;
    }

    private volatile long deadline = Long.MAX_VALUE;
    private final List<String> notices = Collections.synchronizedList(new ArrayList<>());

    public DeviceIdentifier(ScanPlan plan, DeviceEvidence evidence) {
        this(plan, evidence, null);
    }

    DeviceIdentifier(
            ScanPlan plan, DeviceEvidence evidence, TcpScanner.Connector endpointConnector) {
        this(plan, evidence, endpointConnector, null);
    }

    DeviceIdentifier(
            ScanPlan plan,
            DeviceEvidence evidence,
            TcpScanner.Connector endpointConnector,
            Runnable discoveryTask) {
        this.discoveryTask = discoveryTask == null ? this::discoverSsdp : discoveryTask;
        this.plan = plan;
        this.hosts = new HashSet<>(plan.hosts);
        this.evidence = evidence;
        this.endpointConnector =
                endpointConnector == null ? endpointScanner::probe : endpointConnector;
        probeContext = new ProbeContext(plan, evidence, active, () -> deadline, this::stopped);
        tlsProbe = new TlsProbe(probeContext);
        rtspProbe = new RtspProbe(probeContext);
        netBiosProbe = new NetBiosProbe(probeContext);
        upnpProbe = new UpnpProbe(probeContext);
        serviceProbes =
                Arrays.asList(
                        new SmbProbe(probeContext),
                        tlsProbe,
                        rtspProbe,
                        new IppProbe(probeContext),
                        new HttpProbe(probeContext),
                        new BannerProbe(probeContext));
    }

    public void cancel() {
        cancelled.set(true);
        endpointScanner.cancel();
        synchronized (this) {
            if (discoveryFuture != null) discoveryFuture.cancel(true);
            if (discoveryWorker != null) discoveryWorker.shutdownNow();
        }
        if (hostnameLookup != null) hostnameLookup.cancel();
        for (Closeable socket : active)
            try {
                socket.close();
            } catch (IOException ignored) {
            }
    }

    public boolean isTimedOut() {
        return timedOut;
    }

    void addNotices(Collection<String> items) { synchronized (notices) { notices.addAll(items); } }\n\n    public List<String> notices() {
        synchronized (notices) {
            List<String> result = new ArrayList<>(notices);
            if (hostnameLookup != null) result.addAll(hostnameLookup.notices());
            return result;
        }
    }

    private boolean stopped() {
        return cancelled.get()
                || Thread.currentThread().isInterrupted()
                || System.nanoTime() >= deadline;
    }

    public void identify(List<TcpScanner.Result> checks) throws InterruptedException {
        deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(plan.mode.identificationSeconds);
        if (cancelled.get()) return;
        if (!awaitDiscovery(deadline)) return;
        advertised = evidence.endpoints();
        for (TcpScanner.Result check : checks) {
            initialChecks.put(check.host + ":" + check.port, check);
            if (check.state == TcpScanner.State.OPEN || check.state == TcpScanner.State.CLOSED)
                respondingHosts.add(check.host);
        }
        ExecutorService workers = Executors.newFixedThreadPool(8);
        try {
            Map<String, List<Integer>> open = new LinkedHashMap<>();
            for (TcpScanner.Result check : checks)
                if (check.state == TcpScanner.State.OPEN)
                    open.computeIfAbsent(check.host, k -> new ArrayList<>()).add(check.port);
            for (String host : identificationOrder(checks)) {
                List<Integer> ports = open.getOrDefault(host, Collections.emptyList());
                workers.submit(
                        () -> {
                            try {
                                fingerprint(host, ports);
                            } catch (RuntimeException error) {
                                failed = true;
                                notices.add(
                                        "Identification failed for "
                                                + host
                                                + ": "
                                                + error.getClass().getSimpleName());
                            }
                            java.util.function.Consumer<String> listener = progressListener;
                            if (listener != null && !cancelled.get()) listener.accept(host);
                        });
            }
            workers.shutdown();
            while (!workers.awaitTermination(100, TimeUnit.MILLISECONDS)) {
                if (stopped()) {
                    timedOut = !cancelled.get() && System.nanoTime() >= deadline;
                    cancel();
                    workers.shutdownNow();
                }
            }
            if (!cancelled.get() && System.nanoTime() >= deadline) timedOut = true;
        } catch (InterruptedException e) {
            cancel();
            throw e;
        } finally {
            workers.shutdownNow();
            cancel();
        }
    }

    List<String> identificationOrder(List<TcpScanner.Result> checks) {
        Set<String> responders = new HashSet<>();
        for (TcpScanner.Result check : checks)
            if (check.state == TcpScanner.State.OPEN || check.state == TcpScanner.State.CLOSED)
                responders.add(check.host);
        List<String> ordered = new ArrayList<>(plan.hosts);
        ordered.sort(
                Comparator.comparingInt(
                        host ->
                                responders.contains(host) || evidence.hasObservations(host)
                                        ? 0
                                        : 1));
        return ordered;
    }

    private void discoverSsdp() {
        SsdpDiscovery.Result result = new SsdpDiscovery(probeContext, hosts).discover();
        descriptionLocations = result.locations;
        if (!result.failure.isEmpty()) {
            failed = true;
            if (!cancelled.get()) notices.add("SSDP discovery unavailable: " + result.failure);
        }
    }

    private Map<String, String> descriptionLocations = Collections.emptyMap();

    public static boolean allowedLocation(String location, String ip) {
        return UpnpProbe.allowedLocation(location, ip);
    }

    private void fingerprint(String host, List<Integer> ports) {
        if (stopped()) return;

        // PTR records may be cached: query only responders or independently announced devices.
        boolean responding = !ports.isEmpty() || evidence.hasObservations(host);
        responding = responding || respondingHosts.contains(host);
        boolean netbiosDone = !responding;
        if (netbiosDone) {
            netBiosProbe.netbios(host);
            responding = evidence.hasObservations(host);
        }
        String location = descriptionLocations.get(host);
        if (location != null) upnpProbe.description(host, location);
        Map<Integer, String> probes = new LinkedHashMap<>();
        for (DeviceEvidence.Endpoint endpoint :
                advertised.getOrDefault(host, Collections.emptyList())) {
            if (stopped()) break;
            TcpScanner.Result result = verifyEndpoint(host, endpoint.port);
            if (result == null) break;
            endpointChecks.add(result);
            evidence.add(
                    host,
                    endpoint.source,
                    "endpointCheck",
                    "tcp/"
                            + endpoint.port
                            + " "
                            + result.state
                            + " ("
                            + result.attempts
                            + " attempt(s))");
            if (result.state == TcpScanner.State.OPEN)
                probes.put(endpoint.port, endpoint.serviceType);
        }
        for (int port : ports) probes.putIfAbsent(port, "");
        List<Map.Entry<Integer, String>> prioritized = new ArrayList<>(probes.entrySet());
        prioritized.sort(
                Comparator.comparingInt(item -> probePriority(item.getKey(), item.getValue())));
        int reads = 0, unsupported = 0;
        for (Map.Entry<Integer, String> probe : prioritized) {
            int port = probe.getKey();
            String type = probe.getValue();
            if (stopped() || reads >= plan.mode.fingerprintLimit) break;
            DeviceProbe selected = probeFor(port, type);
            if (selected == null) {
                unsupported++;
            } else {
                reads++;
                selected.probe(host, port, type);
            }
        }
        if (responding && hostnameLookup != null && !stopped())
            hostnameLookup.lookup(host, deadline, this::stopped);
        if (!netbiosDone && !stopped()) netBiosProbe.netbios(host);
        if (responding || evidence.hasObservations(host))
            evidence.add(
                    host,
                    "Analysis",
                    "identificationStatus",
                    IdentificationStatus.of(false, stopped()).wireValue);
        if (!prioritized.isEmpty())
            evidence.add(
                    host,
                    "Analysis",
                    "probeCoverage",
                    reads
                            + " attempted, "
                            + unsupported
                            + " unsupported, "
                            + Math.max(0, prioritized.size() - reads - unsupported)
                            + " not attempted within budget");
    }

    DeviceProbe probeFor(int port, String serviceType) {
        for (DeviceProbe candidate : serviceProbes) {
            if (candidate.supports(port, serviceType)) return candidate;
        }
        return null;
    }

    static boolean isIppEndpoint(int port, String type) {
        return IppProbe.matches(port, type);
    }

    static boolean isHttpEndpoint(int port, String type) {
        return HttpProbe.matches(port, type);
    }

    static boolean isSmbEndpoint(int port, String type) {
        return SmbProbe.matches(port, type);
    }

    static boolean isTlsEndpoint(int port, String type) {
        return TlsProbe.matches(port, type);
    }

    static boolean isRtspEndpoint(int port, String type) {
        return RtspProbe.matches(port, type);
    }

    static int probePriority(int port, String type) {
        if (isIppEndpoint(port, type)) return 0;
        if (!type.isEmpty()) return 1;
        if (isSmbEndpoint(port, type)
                || isTlsEndpoint(port, type)
                || isHttpEndpoint(port, type)
                || isRtspEndpoint(port, type)) return 2;
        return 3;
    }

    TcpScanner.Result verifyEndpoint(String host, int port) {
        if (!hosts.contains(host) || port < 1 || port > 65535 || stopped()) return null;
        TcpScanner.Result cached = initialChecks.get(host + ":" + port);
        if (cached != null && cached.state != TcpScanner.State.NO_RESPONSE) return cached;
        int timeout = plan.timeoutMs, attempts = 0;
        TcpScanner.State state = TcpScanner.State.ERROR;
        for (int retry = 0; retry <= plan.mode.retries; retry++) {
            if (stopped()) break;
            int remaining =
                    (int)
                            Math.min(
                                    3000,
                                    TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()));
            timeout = Math.max(1, Math.min(timeout, remaining));
            attempts++;
            state = endpointConnector.connect(host, port, timeout);
            if (state != TcpScanner.State.NO_RESPONSE || retry == plan.mode.retries) break;
            timeout = plan.mode.nextTimeout(timeout);
        }
        return attempts == 0 || cancelled.get()
                ? null
                : new TcpScanner.Result(host, port, state, attempts, timeout);
    }

    void rtsp(String host, int port) {
        rtspProbe.probe(host, port, "");
    }

    void tls(String host, int port, String type) {
        tlsProbe.probe(host, port, type);
    }

    String read(String host, int port, String request, int limit) {
        return probeContext.read(host, port, request, limit);
    }

    byte[] readBytes(String host, int port, byte[] request, int limit) {
        return probeContext.readBytes(host, port, request, limit);
    }
}
