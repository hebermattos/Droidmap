package com.netmap.android;

import android.content.Context;
import android.net.Uri;
import android.os.Bundle;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Owns pending export state and report I/O; callers execute writes off the main thread. */
final class ReportExporter {
    private static final int MAX_BUNDLE_CHARACTERS = 100000;
    private final Context context;
    private ExportRequest pending = new ExportRequest("", 0);

    ReportExporter(Context context) {
        this.context = context;
    }

    void capture(String report, long runId) {
        pending = new ExportRequest(report, runId);
    }

    void clear() {
        pending = new ExportRequest("", 0);
    }

    ExportRequest take() {
        ExportRequest request = pending;
        clear();
        return request;
    }

    void restore(Bundle state) {
        pending =
                new ExportRequest(
                        state.getString("pendingExport", ""),
                        state.getLong("pendingExportRunId", 0));
    }

    void saveState(Bundle state) {
        if (pending.payload.length() < MAX_BUNDLE_CHARACTERS) {
            state.putString("pendingExport", pending.payload);
        }
        state.putLong("pendingExportRunId", pending.runId);
    }

    void write(Uri uri, ExportRequest request) throws IOException {
        LatestScanStore store =
                new LatestScanStore(new File(context.getFilesDir(), "latest-scan.json"));
        String payload = request.resolve(ScanService.snapshot(), store::load);
        try (OutputStream stream = context.getContentResolver().openOutputStream(uri, "wt")) {
            if (stream == null) throw new IOException("Unable to open destination");
            stream.write(payload.getBytes(StandardCharsets.UTF_8));
        }
    }
}
