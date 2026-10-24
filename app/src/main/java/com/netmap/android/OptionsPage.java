package com.netmap.android;

import android.app.Activity;
import android.app.AlertDialog;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import java.util.function.Consumer;

/** One settings page with collapsible tool sections and a fixed Save/Cancel footer. */
final class OptionsPage {
    private OptionsPage() {}

    interface Actions {
        void useWifi(boolean allAddresses);
    }

    static void show(Activity activity, ScanSettings current, boolean scanning, String page,
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
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Save", null)
                .create();

        Group wifi = new Group(activity, form, "Wi-Fi", "wifi".equals(page));
        Group nmap = new Group(activity, form, "Nmap", false);
        Group nuclei = new Group(activity, form, "Nuclei", false);
        Group bt = new Group(activity, form, "Bluetooth", "bluetooth".equals(page));
        LinearLayout wifiForm=wifi.body, nmapForm=nmap.body, nucleiForm=nuclei.body, bluetoothForm=bt.body;
        TextView targetHelp = new TextView(activity);
        targetHelp.setText("Enter an IP or CIDR on the main screen, or select the connected Wi-Fi range.");
        wifiForm.addView(targetHelp);
        action(activity, wifiForm, "Use Wi-Fi network", !scanning, () -> {
            dialog.dismiss();
            actions.useWifi(false);
        });
        action(activity, wifiForm, "Scan all Wi-Fi IPs", !scanning, () -> {
            dialog.dismiss();
            actions.useWifi(true);
        });

        ScanOptionsEditor scanOptions = new ScanOptionsEditor(activity, wifiForm, current, !scanning);

        TextView nmapHint = new TextView(activity);
        nmapHint.setText("Nmap runs from its own button after Discovery. Only confirmed open ports are passed to it.");
        nmapForm.addView(nmapHint);
        Spinner intensity = spinner(activity, nmapForm, "Service/version intensity",
                new String[] {"0 — Minimal", "1", "2 — Light", "3", "4", "5", "6",
                        "7 — Nmap default", "8", "9 — All probes"}, current.nmapVersionIntensity);
        EditText args = field(activity, nmapForm, "Additional Nmap arguments (optional)", current.nmapArgs);
        args.setHint("-n --reason -T3");
        intensity.setEnabled(!scanning);
        args.setEnabled(!scanning);

        NucleiSettingsStore nucleiStore = new NucleiSettingsStore(activity);
        int coverageMask = nucleiStore.load();
        CheckBox[] coverage = new CheckBox[NucleiTemplates.LABELS.length];
        for (int i=0;i<coverage.length;i++) {
            coverage[i] = new CheckBox(activity);
            coverage[i].setText(NucleiTemplates.LABELS[i] + " · "
                    + NucleiTemplates.files(1 << i).size() + " templates");
            coverage[i].setChecked((coverageMask & (1 << i)) != 0);
            coverage[i].setEnabled(!scanning);
            nucleiForm.addView(coverage[i]);
        }
        TextView coverageHelp = new TextView(activity);
        coverageHelp.setText("Read-only HTTP checks on the selected verified web port. Select at least one group. Diagnostic interfaces are informational; no matches do not mean the endpoint is secure.");
        nucleiForm.addView(coverageHelp);

        BluetoothSettingsStore bluetoothStore = new BluetoothSettingsStore(activity);
        BluetoothSettings bluetooth = bluetoothStore.load();
        Spinner bluetoothMode = spinner(activity, bluetoothForm, "Discovery mode", BluetoothSettings.MODES,
                java.util.Arrays.asList(BluetoothSettings.MODES).indexOf(bluetooth.mode));
        Spinner bluetoothDiscovery = spinner(activity, bluetoothForm, "Discovery duration", BluetoothSettings.LABELS,
                BluetoothSettings.index(bluetooth.discoverySeconds));
        Spinner bluetoothSdp = spinner(activity, bluetoothForm, "SDP response timeout", BluetoothSettings.LABELS,
                BluetoothSettings.index(bluetooth.sdpSeconds));
        Spinner bluetoothGatt = spinner(activity, bluetoothForm, "GATT inspection timeout (per attempt)", BluetoothSettings.LABELS,
                BluetoothSettings.index(bluetooth.gattSeconds));
        Spinner bluetoothRead = spinner(activity, bluetoothForm, "Characteristic read timeout", BluetoothSettings.LABELS,
                BluetoothSettings.index(bluetooth.readSeconds));
        TextView bluetoothHelp = new TextView(activity);
        bluetoothHelp.setText("No limit waits until Stop or an Android outcome. GATT includes connection, service discovery and reads per attempt. Changes apply to the next run. Android's own limits still apply.");
        bluetoothForm.addView(bluetoothHelp);
        for (Spinner option : new Spinner[]{bluetoothMode, bluetoothDiscovery, bluetoothSdp, bluetoothGatt, bluetoothRead})
            option.setEnabled(!scanning);

        dialog.setOnShowListener(ignored -> {
            android.view.Window window = dialog.getWindow();
            if (window != null) window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT,
                    Math.round(activity.getResources().getDisplayMetrics().heightPixels * 0.88f));
            Button save=dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            save.setEnabled(!scanning);
            save.setOnClickListener(v -> {
                ScanSettings updated = scanOptions.read(args.getText().toString(),
                        intensity.getSelectedItemPosition());
                if (updated == null) { wifi.expand(); return; }
                BluetoothSettings updatedBluetooth = new BluetoothSettings(
                        BluetoothSettings.MODES[bluetoothMode.getSelectedItemPosition()],
                        BluetoothSettings.SECONDS[bluetoothDiscovery.getSelectedItemPosition()],
                        BluetoothSettings.SECONDS[bluetoothSdp.getSelectedItemPosition()],
                        BluetoothSettings.SECONDS[bluetoothGatt.getSelectedItemPosition()],
                        BluetoothSettings.SECONDS[bluetoothRead.getSelectedItemPosition()]);
                int selectedCoverage = 0;
                for (int i=0;i<coverage.length;i++) if (coverage[i].isChecked()) selectedCoverage |= 1 << i;
                if (selectedCoverage == 0) {
                    nuclei.expand();
                    Toast.makeText(activity, "Select at least one Nuclei coverage group", Toast.LENGTH_LONG).show();
                    return;
                }
                nucleiStore.save(selectedCoverage);
                bluetoothStore.save(updatedBluetooth);
                onSave.accept(updated);
                dialog.dismiss();
            });
        });
        dialog.show();
    }

    private static final class Group {
        final Button toggle;
        final LinearLayout body;
        final String name;
        Group(Activity activity, LinearLayout parent, String name, boolean expanded) {
            this.name=name;
            toggle=new Button(activity);
            toggle.setAllCaps(false);
            parent.addView(toggle,new LinearLayout.LayoutParams(-1,-2));
            body=new LinearLayout(activity);
            body.setOrientation(LinearLayout.VERTICAL);
            parent.addView(body,new LinearLayout.LayoutParams(-1,-2));
            setExpanded(expanded);
            toggle.setOnClickListener(v -> setExpanded(body.getVisibility()!=View.VISIBLE));
        }
        void expand() {setExpanded(true);}
        private void setExpanded(boolean expanded) {
            body.setVisibility(expanded?View.VISIBLE:View.GONE);
            toggle.setText((expanded?"− ":"+ ")+name);
            toggle.setContentDescription((expanded?"Collapse ":"Expand ")+name+" settings");
        }
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
