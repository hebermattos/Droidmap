package com.netmap.android;

import static org.junit.Assert.*;

import org.json.*;
import org.junit.Test;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/** Behavior contracts across the extracted collaborators and serialization boundaries. */
public class RefactoringTest {
    private static final String IP = "192.168.1.1";

    private ScanSnapshot snapshot(long id, String report) {
        return new ScanSnapshot(id, false, false, 1, 1, IP, "Done", report, "");
    }

    @Test
    public void capturedExportSurvivesANewerScan() throws Exception {
        ExportRequest request = new ExportRequest("original", 1);
        assertEquals(
                "original",
                request.resolve(
                        snapshot(2, "new"),
                        () -> {
                            throw new AssertionError(
                                    "Captured exports must not read latest storage");
                        }));
    }

    @Test
    public void restoredExportLoadsOnlyTheRequestedRun() throws Exception {
        ExportRequest request = new ExportRequest("", 1);
        assertEquals("stored", request.resolve(snapshot(2, "new"), () -> snapshot(1, "stored")));
        assertEquals(
                "live",
                request.resolve(
                        snapshot(1, "live"),
                        () -> {
                            throw new AssertionError("Matching live result must not read storage");
                        }));
        assertThrows(IOException.class, () -> request.resolve(null, () -> snapshot(2, "new")));
        assertThrows(
                IOException.class, () -> request.resolve(snapshot(1, ""), () -> snapshot(1, "")));
    }

    @Test
    public void scanSettingsKeepCustomOptionsAndValidateBounds() {
        ScanSettings settings = new ScanSettings("22,8000-8002", 350, ScanPlan.Mode.FAST, false);
        assertEquals("Fast • 4 ports • 350 ms • Nmap On", settings.summary());
        assertTrue(settings.nmap);
        ScanSettings complete = settings.completeDefaults();
        assertEquals(ScanPlan.Mode.COMPLETE, complete.mode);
        assertEquals(ScanPlan.COMPLETE_PORTS, complete.ports);
        assertEquals(350, complete.timeoutMs);
        assertFalse(complete.adaptive);
        assertTrue(complete.nmap);
        assertEquals("22,8000-8002", settings.ports);
        assertThrows(
                IllegalArgumentException.class,
                () -> new ScanSettings("80", 99, ScanPlan.Mode.FAST, true));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ScanSettings("80", 3001, ScanPlan.Mode.FAST, true));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ScanSettings("0", 200, ScanPlan.Mode.FAST, true));
    }

    private android.content.SharedPreferences preferences(Map<String, Object> values) {
        return (android.content.SharedPreferences)
                java.lang.reflect.Proxy.newProxyInstance(
                        getClass().getClassLoader(),
                        new Class<?>[] {android.content.SharedPreferences.class},
                        (proxy, method, arguments) -> {
                            if (method.getName().equals("edit")) {
                                Map<String, Object> staged = new HashMap<>();
                                return java.lang.reflect.Proxy.newProxyInstance(
                                        getClass().getClassLoader(),
                                        new Class<?>[] {
                                            android.content.SharedPreferences.Editor.class
                                        },
                                        (editor, operation, items) -> {
                                            if (operation.getName().startsWith("put")) {
                                                staged.put((String) items[0], items[1]);
                                                return editor;
                                            }
                                            if (operation.getName().equals("apply")) {
                                                values.putAll(staged);
                                                return null;
                                            }
                                            throw new AssertionError(
                                                    "Unexpected editor call: "
                                                            + operation.getName());
                                        });
                            }
                            if (method.getName().startsWith("get") && arguments.length == 2) {
                                return values.getOrDefault((String) arguments[0], arguments[1]);
                            }
                            throw new AssertionError(
                                    "Unexpected preference call: " + method.getName());
                        });
    }

    @Test
    public void settingsMigrationRunsOnceAndKeepsCustomValues() {
        Map<String, Object> values = new HashMap<>();
        values.put("timeout", 500);
        values.put("ports", "22,8081");
        ScanSettingsStore store = new ScanSettingsStore(preferences(values));
        ScanSettings migrated = store.load();
        assertEquals(200, migrated.timeoutMs);
        assertEquals("22,8081", migrated.ports);
        store.save(new ScanSettings("80,443", 500, ScanPlan.Mode.COMPLETE, false));
        ScanSettings restored = store.load();
        assertEquals(500, restored.timeoutMs);
        assertEquals("80,443", restored.ports);
        assertEquals(ScanPlan.Mode.COMPLETE, restored.mode);
        assertFalse(restored.adaptive);
        assertTrue(restored.nmap);
    }

    @Test
    public void firstSettingsLoadPreservesACustomTimeout() {
        Map<String, Object> values = new HashMap<>();
        values.put("timeout", 350);
        assertEquals(350, new ScanSettingsStore(preferences(values)).load().timeoutMs);
    }

    @Test
    public void actualProbeRoutingPreservesAnnouncementsAndPrecedence() {
        DeviceIdentifier identifier =
                new DeviceIdentifier(
                        new ScanPlan(IP, "80", 200), new DeviceEvidence(Collections.singleton(IP)));
        try {
            assertTrue(identifier.probeFor(445, "") instanceof SmbProbe);
            assertTrue(identifier.probeFor(554, "") instanceof RtspProbe);
            assertTrue(identifier.probeFor(631, "") instanceof IppProbe);
            assertTrue(identifier.probeFor(80, "_https._tcp.") instanceof TlsProbe);
            assertTrue(identifier.probeFor(12345, "_http._tcp.") instanceof HttpProbe);
            assertTrue(identifier.probeFor(631, "_ipps._tcp.") instanceof TlsProbe);
            assertTrue(identifier.probeFor(22, "") instanceof BannerProbe);
            assertNull(identifier.probeFor(12345, ""));
            assertNull(identifier.probeFor(9100, "_printer._tcp."));
        } finally {
            identifier.cancel();
        }
    }

    @Test
    public void extractedHttpProbeCollectsEvidenceAndReleasesItsSocket() throws Exception {
        String host = "127.0.0.1";
        DeviceEvidence evidence = new DeviceEvidence(Collections.singleton(host));
        Set<Closeable> active = ConcurrentHashMap.newKeySet();
        ProbeContext context =
                new ProbeContext(
                        new ScanPlan(IP, "80", 200),
                        evidence,
                        active,
                        () -> Long.MAX_VALUE,
                        () -> false);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Future<String> served =
                    worker.submit(
                            () -> {
                                try (Socket socket = server.accept()) {
                                    socket.setSoTimeout(2000);
                                    BufferedReader input =
                                            new BufferedReader(
                                                    new InputStreamReader(
                                                            socket.getInputStream(),
                                                            StandardCharsets.US_ASCII));
                                    String request = input.readLine();
                                    while (!input.readLine().isEmpty()) {}
                                    socket.getOutputStream()
                                            .write(
                                                    "HTTP/1.0 200 OK\\r\\nServer: Example\\r\\n\\r\\n<title>Office device</title>"
                                                            .getBytes(StandardCharsets.US_ASCII));
                                    return request;
                                }
                            });
            new HttpProbe(context).probe(host, server.getLocalPort(), "_http._tcp.");
            assertEquals("GET / HTTP/1.0", served.get(3, TimeUnit.SECONDS));
            assertEquals("Example", DeviceEvidence.first(evidence.observations(host), "server"));
            assertEquals(
                    "Office device",
                    DeviceEvidence.first(evidence.observations(host), "httpTitle"));
            assertTrue(active.isEmpty());
        } finally {
            worker.shutdownNow();
        }
    }

    @Test
    public void expiredProbeBudgetStartsNoConnection() {
        Set<Closeable> active = ConcurrentHashMap.newKeySet();
        ProbeContext context =
                new ProbeContext(
                        new ScanPlan(IP, "80", 200),
                        new DeviceEvidence(Collections.singleton(IP)),
                        active,
                        () -> 0L,
                        () -> true);
        assertThrows(SocketTimeoutException.class, () -> context.remainingTimeout(500));
        assertArrayEquals(new byte[0], context.readBytes(IP, 80, null, 32));
        assertTrue(active.isEmpty());
    }

    @Test
    public void typedConfidenceKeepsExistingReportLabels() throws Exception {
        DeviceEvidence evidence = new DeviceEvidence(Collections.singleton(IP));
        evidence.add(IP, "UPnP", "modelName", "Example");
        evidence.add(IP, "mDNS TXT", "modelHint", "Example");
        DeviceProfile profile = new DeviceProfile(evidence.observations(IP));
        assertEquals(DeviceConfidence.CORROBORATED, profile.modelConfidence);
        JSONObject report =
                new JSONObject(
                        ScanReport.preview(
                                IP,
                                Collections.emptyList(),
                                Collections.emptyList(),
                                evidence.snapshot()));
        JSONObject device = report.getJSONArray("devices").getJSONObject(0);
        assertEquals("Corroborated, unverified", device.getString("modelConfidence"));
        assertEquals("Corroborated, unverified", device.getString("identityConfidence"));
        assertEquals(IdentificationStatus.CANCELLED, IdentificationStatus.of(true, false));
        assertEquals("cancelled", IdentificationStatus.of(true, true).wireValue);
        assertEquals("partial", IdentificationStatus.of(false, true).wireValue);
        assertEquals("completed", IdentificationStatus.of(false, false).wireValue);
    }
}
