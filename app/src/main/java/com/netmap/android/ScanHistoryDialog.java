package com.netmap.android;

import org.json.*;

import java.util.*;

/** Asynchronous history presentation, guarded by the calling Activity's lifecycle. */
final class ScanHistoryDialog {
    private ScanHistoryDialog() {}

    static void show(
            android.app.Activity activity,
            java.util.concurrent.ExecutorService background,
            java.util.function.BooleanSupplier canShow,
            java.util.function.BooleanSupplier alive,
            java.util.function.Consumer<String> onError) {
        ScanHistory history =
                new ScanHistory(new java.io.File(activity.getFilesDir(), "scan-history.json"));
        background.execute(
                () -> {
                    try {
                        JSONArray entries = history.load();
                        String[] labels = new String[entries.length()];
                        for (int i = 0; i < entries.length(); i++) {
                            JSONObject entry = entries.getJSONObject(i);
                            labels[i] =
                                    new java.text.SimpleDateFormat("MM-dd HH:mm", Locale.US)
                                                    .format(new Date(entry.getLong("time")))
                                            + " • "
                                            + entry.getString("target");
                        }
                        activity.runOnUiThread(
                                () -> {
                                    if (!canShow.getAsBoolean()) return;
                                    if (labels.length == 0) {
                                        new android.app.AlertDialog.Builder(activity)
                                                .setMessage("No completed scans saved yet.")
                                                .setPositiveButton("OK", null)
                                                .show();
                                        return;
                                    }
                                    new android.app.AlertDialog.Builder(activity)
                                            .setTitle("Recent scans")
                                            .setItems(
                                                    labels,
                                                    (dialog, index) -> {
                                                        try {
                                                            new android.app.AlertDialog.Builder(
                                                                            activity)
                                                                    .setTitle("Scan summary")
                                                                    .setMessage(
                                                                            ScanHistory.describe(
                                                                                    entries
                                                                                            .getJSONObject(
                                                                                                    index)))
                                                                    .setPositiveButton("OK", null)
                                                                    .show();
                                                        } catch (Exception ignored) {
                                                        }
                                                    })
                                            .setNegativeButton("Close", null)
                                            .show();
                                });
                    } catch (Exception e) {
                        activity.runOnUiThread(
                                () -> {
                                    if (alive.getAsBoolean()) onError.accept("History unavailable");
                                });
                    }
                });
    }
}
