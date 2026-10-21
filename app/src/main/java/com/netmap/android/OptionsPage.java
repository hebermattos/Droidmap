package com.netmap.android;

import android.app.Activity;
import android.app.AlertDialog;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import java.util.function.Consumer;

/** Single scrollable entry point for scan options, target shortcuts and report actions. */
final class OptionsPage {
    private OptionsPage() {}

    interface Actions {
        void useWifi(boolean allAddresses);
        void openHistory();
        void reanalyzeDevice();
        void openReport();
        void exportJson();
    }

    static void show(Activity activity, ScanSettings current, boolean scanning,
            boolean hasDevices, boolean hasReport, boolean canExport,
            Consumer<ScanSettings> onSave, Actions actions) {
        float density = activity.getResources().getDisplayMetrics().density;
        int pad = Math.round(18 * density);
        LinearLayout form = new LinearLayout(activity);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(pad, pad / 2, pad, pad);
        ScrollView scroll = new ScrollView(activity);
        scroll.setFillViewport(true);
        scroll.addView(form);
        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setTitle("Options")
                .setView(scroll)
                .setPositiveButton("Done", null)
                .create();

        heading(activity, form, "Scan targets");
        TextView targetHelp = new TextView(activity);
        targetHelp.setText("Enter an IP or CIDR on the main screen, or select the connected Wi-Fi range.");
        form.addView(targetHelp);
        action(activity, form, "Use Wi-Fi network", !scanning, () -> {
            dialog.dismiss();
            actions.useWifi(false);
        });
        action(activity, form, "Scan all Wi-Fi IPs", !scanning, () -> {
            dialog.dismiss();
            actions.useWifi(true);
        });

        heading(activity, form, "TCP discovery");
        ScanOptionsEditor scanOptions = new ScanOptionsEditor(activity, form, current, !scanning);

        heading(activity, form, "Nmap");
        TextView nmapHint = new TextView(activity);
        nmapHint.setText("Nmap runs from its own button after Discovery. Only confirmed open ports are passed to it.");
        form.addView(nmapHint);
        Spinner intensity = spinner(activity, form, "Service/version intensity",
                new String[] {"0 — Minimal", "1", "2 — Light", "3", "4", "5", "6",
                        "7 — Nmap default", "8", "9 — All probes"}, current.nmapVersionIntensity);
        EditText args = field(activity, form, "Additional Nmap arguments (optional)", current.nmapArgs);
        args.setHint("-n --reason -T3");
        intensity.setEnabled(!scanning);
        args.setEnabled(!scanning);

        heading(activity, form, "Nuclei coverage");
        NucleiSettingsStore nucleiStore = new NucleiSettingsStore(activity);
        int coverageMask = nucleiStore.load();
        CheckBox[] coverage = new CheckBox[NucleiTemplates.LABELS.length];
        for (int i=0;i<coverage.length;i++) {
            coverage[i] = new CheckBox(activity);
            coverage[i].setText(NucleiTemplates.LABELS[i] + " · 3 templates");
            coverage[i].setChecked((coverageMask & (1 << i)) != 0);
            coverage[i].setEnabled(!scanning);
            form.addView(coverage[i]);
        }
        TextView coverageHelp = new TextView(activity);
        coverageHelp.setText("Read-only HTTP checks on the selected verified web port. Select at least one group. Diagnostic interfaces are informational; no matches do not mean the endpoint is secure.");
        form.addView(coverageHelp);

        heading(activity, form, "Bluetooth");
        BluetoothSettingsStore bluetoothStore = new BluetoothSettingsStore(activity);
        BluetoothSettings bluetooth = bluetoothStore.load();
        Spinner bluetoothMode = spinner(activity, form, "Discovery mode", BluetoothSettings.MODES,
                java.util.Arrays.asList(BluetoothSettings.MODES).indexOf(bluetooth.mode));
        Spinner bluetoothDiscovery = spinner(activity, form, "Discovery duration", BluetoothSettings.LABELS,
                BluetoothSettings.index(bluetooth.discoverySeconds));
        Spinner bluetoothSdp = spinner(activity, form, "SDP response timeout", BluetoothSettings.LABELS,
                BluetoothSettings.index(bluetooth.sdpSeconds));
        Spinner bluetoothGatt = spinner(activity, form, "GATT inspection timeout (per attempt)", BluetoothSettings.LABELS,
                BluetoothSettings.index(bluetooth.gattSeconds));
        Spinner bluetoothRead = spinner(activity, form, "Characteristic read timeout", BluetoothSettings.LABELS,
                BluetoothSettings.index(bluetooth.readSeconds));
        TextView bluetoothHelp = new TextView(activity);
        bluetoothHelp.setText("No limit waits until Stop or an Android outcome. GATT includes connection, service discovery and reads per attempt. Changes apply to the next run. Android's own limits still apply.");
        form.addView(bluetoothHelp);
        for (Spinner option : new Spinner[]{bluetoothMode, bluetoothDiscovery, bluetoothSdp, bluetoothGatt, bluetoothRead})
            option.setEnabled(!scanning);

        // Nuclei intentionally has no duplicated enable toggle: its separate tool button starts it.
        heading(activity, form, "History and reports");
        action(activity, form, "History", !scanning, () -> { dialog.dismiss(); actions.openHistory(); });
        action(activity, form, "Reanalyze a device", !scanning && hasDevices,
                () -> { dialog.dismiss(); actions.reanalyzeDevice(); });
        action(activity, form, "Full report", hasReport,
                () -> { dialog.dismiss(); actions.openReport(); });
        action(activity, form, "Export JSON", canExport,
                () -> { dialog.dismiss(); actions.exportJson(); });

        if (!scanning) {
            heading(activity, form, "Save settings");
            action(activity, form, "Save settings", true, () -> {
                ScanSettings updated = scanOptions.read(args.getText().toString(),
                        intensity.getSelectedItemPosition());
                if (updated == null) return;
                BluetoothSettings updatedBluetooth = new BluetoothSettings(
                        BluetoothSettings.MODES[bluetoothMode.getSelectedItemPosition()],
                        BluetoothSettings.SECONDS[bluetoothDiscovery.getSelectedItemPosition()],
                        BluetoothSettings.SECONDS[bluetoothSdp.getSelectedItemPosition()],
                        BluetoothSettings.SECONDS[bluetoothGatt.getSelectedItemPosition()],
                        BluetoothSettings.SECONDS[bluetoothRead.getSelectedItemPosition()]);
                int selectedCoverage = 0;
                for (int i=0;i<coverage.length;i++) if (coverage[i].isChecked()) selectedCoverage |= 1 << i;
                if (selectedCoverage == 0) {
                    Toast.makeText(activity, "Select at least one Nuclei coverage group", Toast.LENGTH_LONG).show();
                    return;
                }
                nucleiStore.save(selectedCoverage);
                bluetoothStore.save(updatedBluetooth);
                onSave.accept(updated);
                dialog.dismiss();
            });
        } else {
            TextView disabled = new TextView(activity);
            disabled.setText("Settings and target selection are unavailable during a running scan.");
            form.addView(disabled);
        }
        dialog.setOnShowListener(ignored -> {
            android.view.Window window = dialog.getWindow();
            if (window != null) window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT,
                    Math.round(activity.getResources().getDisplayMetrics().heightPixels * 0.88f));
        });
        dialog.show();
    }

    private static void heading(Activity activity, LinearLayout form, String name) {
        TextView title = new TextView(activity);
        title.setText(name);
        title.setTextSize(17);
        title.setTypeface(null, android.graphics.Typeface.BOLD);
        title.setPadding(0, Math.round(18 * activity.getResources().getDisplayMetrics().density), 0, 4);
        form.addView(title);
    }

    private static EditText field(Activity activity, LinearLayout form, String label, String value) {
        TextView caption = new TextView(activity);
        caption.setText(label);
        form.addView(caption);
        EditText field = new EditText(activity);
        field.setSingleLine(true);
        field.setText(value);
        form.addView(field);
        return field;
    }

    private static Spinner spinner(Activity activity, LinearLayout form, String label,
            String[] options, int position) {
        TextView caption = new TextView(activity);
        caption.setText(label);
        form.addView(caption);
        Spinner spinner = new Spinner(activity);
        spinner.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_spinner_dropdown_item, options));
        spinner.setSelection(position);
        form.addView(spinner);
        return spinner;
    }

    private static void action(Activity activity, LinearLayout form, String label,
            boolean enabled, Runnable action) {
        Button button = new Button(activity);
        button.setText(label);
        button.setEnabled(enabled);
        button.setOnClickListener(v -> action.run());
        form.addView(button);
    }
}
