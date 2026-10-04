package com.netmap.android;

import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

/** One durable latest result, replaced atomically. Running markers never imply a finished scan. */
final class LatestScanStore {
    static final int MAX_BYTES=32*1024*1024;
    private final File file;
    LatestScanStore(File file) { this.file=file; }
    void save(ScanSnapshot state) throws IOException {
        try {
            JSONObject record=new JSONObject().put("runId",state.runId).put("running",state.running)
                .put("done",state.done).put("total",state.total).put("target",state.target)
                .put("message",state.message).put("report",state.report).put("text",state.text);
            byte[] bytes=record.toString().getBytes(StandardCharsets.UTF_8);
            if(bytes.length>MAX_BYTES) throw new IOException("Latest result exceeds storage limit");
            File temp=new File(file.getPath()+".tmp");
            try {
                try(FileOutputStream out=new FileOutputStream(temp)) { out.write(bytes); out.getFD().sync(); }
                try { Files.move(temp.toPath(),file.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING); }
                catch(AtomicMoveNotSupportedException e) { Files.move(temp.toPath(),file.toPath(),StandardCopyOption.REPLACE_EXISTING); }
            } finally { Files.deleteIfExists(temp.toPath()); }
        } catch(IOException e) { throw e; }
        catch(Exception e) { throw new IOException("Invalid latest result",e); }
    }
    ScanSnapshot load() throws IOException {
        if(!file.exists()) return ScanSnapshot.ready();
        if(file.length()>MAX_BYTES) throw new IOException("Latest result exceeds storage limit");
        try {
            JSONObject record=new JSONObject(new String(Files.readAllBytes(file.toPath()),StandardCharsets.UTF_8));
            long id=record.getLong("runId"); String target=record.getString("target");
            if(record.getBoolean("running")) return new ScanSnapshot(id,false,false,0,record.getInt("total"),target,
                "Previous scan interrupted. Start again to rescan.","","");
            String report=record.getString("report");
            if(!report.isEmpty()) new JSONObject(report);
            return new ScanSnapshot(id,false,false,record.getInt("done"),record.getInt("total"),target,
                record.getString("message"),report,record.getString("text"));
        } catch(Exception e) { throw new IOException("Saved result unavailable",e); }
    }
}
