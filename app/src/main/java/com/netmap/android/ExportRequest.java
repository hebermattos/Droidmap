package com.netmap.android;

import java.io.IOException;

/** A captured report or a run-scoped reference after Activity recreation. */
final class ExportRequest {
    interface SnapshotLoader {
        ScanSnapshot load() throws IOException;
    }

    final String payload;
    final long runId;

    ExportRequest(String payload, long runId) {
        this.payload = payload;
        this.runId = runId;
    }

    String resolve(ScanSnapshot live, SnapshotLoader loader) throws IOException {
        if (!payload.isEmpty()) return payload;
        ScanSnapshot saved = live;
        if (saved == null || saved.runId != runId) saved = loader.load();
        if (saved.runId != runId || saved.report.isEmpty()) {
            throw new IOException("Export snapshot no longer available");
        }
        return saved.report;
    }
}
