package com.netmap.android;

import android.widget.*;

/** Edits a copy; only a validated Save action publishes new settings. */
final class ScanSettingsDialog {
    private ScanSettingsDialog() {}

    static void show(
            android.content.Context context,
            ScanSettings current,
            java.util.function.Consumer<ScanSettings> onSave) {
        LinearLayout form = new LinearLayout(context);
        form.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * context.getResources().getDisplayMetrics().density);
        form.setPadding(pad, 0, pad, 0);
        ScanOptionsEditor scanOptions = new ScanOptionsEditor(context, form, current, true);
        ScrollView scroll = new ScrollView(context);
        scroll.addView(form);
        android.app.AlertDialog dialog =
                new android.app.AlertDialog.Builder(context)
                        .setTitle("Scan settings")
                        .setView(scroll)
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Save", null)
                        .create();
        dialog.setOnShowListener(
                ignored ->
                        dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE)
                                .setOnClickListener(
                                        v -> {
                                            ScanSettings updated = scanOptions.read(current.nmapArgs,
                                                    current.nmapVersionIntensity);
                                            if (updated == null) return;
                                            onSave.accept(updated);
                                            dialog.dismiss();
                                        }));
        dialog.show();
    }

    static void showNmap(
            android.content.Context context,
            ScanSettings current,
            java.util.function.Consumer<ScanSettings> onSave) {
        LinearLayout form = new LinearLayout(context);
        form.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * context.getResources().getDisplayMetrics().density);
        form.setPadding(pad, 0, pad, 0);
        CheckBox nmap = new CheckBox(context);
        nmap.setText("Enable Nmap service detection");
        nmap.setChecked(current.nmap);
        form.addView(nmap);
        TextView intensityLabel = new TextView(context);
        intensityLabel.setText("Service/version detection intensity");
        form.addView(intensityLabel);
        Spinner intensity = new Spinner(context);
        intensity.setId(android.view.View.generateViewId());
        intensityLabel.setLabelFor(intensity.getId());
        intensity.setAdapter(new ArrayAdapter<>(context,
                android.R.layout.simple_spinner_dropdown_item,
                new String[] {"0 — Minimal", "1", "2 — Light (default)", "3", "4", "5", "6",
                        "7 — Nmap default", "8", "9 — All probes"}));
        intensity.setSelection(current.nmapVersionIntensity);
        intensity.setEnabled(nmap.isChecked());
        form.addView(intensity);
        TextView intensityHelp = new TextView(context);
        intensityHelp.setText("Higher values try more probes and can take longer. Applies to both Nmap profiles.");
        form.addView(intensityHelp);
        EditText args = field(context, form, "Nmap global parameters (optional)",
                current.nmapArgs, android.view.View.generateViewId());
        args.setHint("-n --reason -T3 --host-timeout 20s");
        args.setEnabled(nmap.isChecked());
        nmap.setOnCheckedChangeListener((button, checked) -> {
            args.setEnabled(checked);
            intensity.setEnabled(checked);
        });
        TextView help = new TextView(context);
        help.setText("Custom arguments are passed directly to Nmap without a shell.");
        form.addView(help);
        ScrollView scroll = new ScrollView(context);
        scroll.addView(form);
        new android.app.AlertDialog.Builder(context)
                .setTitle("Nmap settings")
                .setView(scroll)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Save", (dialog, which) -> onSave.accept(
                        new ScanSettings(current.ports, current.timeoutMs, current.mode,
                                current.adaptive, nmap.isChecked(), args.getText().toString(),
                                intensity.getSelectedItemPosition())))
                .show();
    }

    private static EditText field(
            android.content.Context context,
            LinearLayout layout,
            String label,
            String value,
            int id) {
        TextView caption = new TextView(context);
        caption.setText(label);
        caption.setLabelFor(id);
        layout.addView(caption);
        EditText field = new EditText(context);
        field.setId(id);
        field.setSingleLine(true);
        field.setText(value);
        layout.addView(field);
        return field;
    }
}
