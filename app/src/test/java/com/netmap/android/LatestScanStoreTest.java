package com.netmap.android;

import org.junit.*;
import org.junit.rules.TemporaryFolder;
import java.io.*;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.Assert.*;

public class LatestScanStoreTest {
    @Rule public TemporaryFolder directory=new TemporaryFolder();
    private File file;
    private LatestScanStore store;
    @Before public void setup() { file=new File(directory.getRoot(),"latest.json"); store=new LatestScanStore(file); }
    private ScanSnapshot completed(String message) {
        return new ScanSnapshot(123,false,false,2,2,"192.168.0.1",message,"{\"devices\":[{\"ip\":\"192.168.0.1\",\"reportedName\":\"Impressora\"}]}","Full report\nModel: Test\n");
    }
    @Test public void completedResultSurvivesNewStoreInstance() throws Exception {
        ScanSnapshot expected=completed("Scan completed"); store.save(expected);
        ScanSnapshot restored=new LatestScanStore(file).load();
        assertEquals(expected.report,restored.report); assertEquals(expected.text,restored.text);
        assertEquals(expected.target,restored.target); assertEquals(expected.runId,restored.runId);
        assertEquals(2,restored.done); assertFalse(restored.running); assertFalse(restored.cancellable);
    }
    @Test public void runningMarkerReplacesOldReportAndRestoresAsInterrupted() throws Exception {
        store.save(completed("Scan completed"));
        store.save(new ScanSnapshot(124,true,true,1,200,"192.168.0.0/24","Scanning","", ""));
        ScanSnapshot restored=store.load();
        assertFalse(restored.running); assertTrue(restored.message.contains("interrupted"));
        assertEquals("",restored.report); assertEquals("",restored.text); assertEquals(0,restored.done);
        assertEquals("192.168.0.0/24",restored.target); assertEquals(200,restored.total);
    }
    @Test public void cancelledResultsAreRestoredAsPartial() throws Exception {
        store.save(completed("Cancelled — partial results"));
        assertEquals("Cancelled — partial results",store.load().message); assertFalse(store.load().report.isEmpty());
    }
    @Test public void missingStoreIsReady() throws Exception {
        assertEquals("Ready",store.load().message); assertEquals("",store.load().report);
    }
    @Test public void replacementLeavesNoTemporaryFile() throws Exception {
        store.save(completed("first")); store.save(completed("second"));
        assertEquals("second",store.load().message); assertFalse(new File(file+".tmp").exists());
    }
    @Test public void corruptedDataIsNotReturnedAsSuccess() throws Exception {
        Files.write(file.toPath(),"{broken".getBytes(StandardCharsets.UTF_8));
        try {store.load(); fail("Expected invalid result rejection");} catch(IOException expected) {assertEquals("Saved result unavailable",expected.getMessage());}
    }
    @Test public void largeReportPersistsOutsideActivityBundle() throws Exception {
        String report="{\"value\":\""+String.join("",Collections.nCopies(120000,"x"))+"\"}";
        store.save(new ScanSnapshot(1,false,false,1,1,"192.168.0.1","Scan completed",report,"summary"));
        assertEquals(report,new LatestScanStore(file).load().report);
    }
    @Test public void orphanedTemporaryFileDoesNotReplaceCommittedReport() throws Exception {
        store.save(completed("Scan completed"));
        Files.write(new File(file+".tmp").toPath(),"{partial".getBytes(StandardCharsets.UTF_8));
        assertEquals("Scan completed",store.load().message);
    }
    @Test public void oversizedStoredFileIsRejectedBeforeRead() throws Exception {
        try(RandomAccessFile sparse=new RandomAccessFile(file,"rw")) {sparse.setLength(LatestScanStore.MAX_BYTES+1L);}
        try {store.load(); fail("Expected size limit");} catch(IOException expected) {assertTrue(expected.getMessage().contains("storage limit"));}
    }
    @Test public void fullReportPreservesEndpointPortsAndPartialFlag() throws Exception {
        ScanPlan plan=new ScanPlan("192.168.0.1","80",500);
        List<TcpScanner.Result> selected=Arrays.asList(new TcpScanner.Result("192.168.0.1",80,TcpScanner.State.CLOSED));
        List<TcpScanner.Result> extra=Arrays.asList(new TcpScanner.Result("192.168.0.1",8080,TcpScanner.State.OPEN));
        Map<String,List<DeviceEvidence.Observation>> evidence=new LinkedHashMap<>(); evidence.put("192.168.0.1",Collections.emptyList());
        org.json.JSONObject report=new org.json.JSONObject(ScanReport.json(selected,plan,"192.168.0.1",true,123,evidence,Collections.emptyList(),extra));
        assertTrue(report.getBoolean("cancelled")); assertEquals(8080,report.getJSONArray("advertisedEndpointChecks").getJSONObject(0).getInt("port"));
        assertEquals("192.168.0.1",report.getJSONArray("devices").getJSONObject(0).getString("ip"));
    }
}
