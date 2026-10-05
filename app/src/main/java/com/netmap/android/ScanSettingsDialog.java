package com.netmap.android;

import android.text.InputType;
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
        TextView label = new TextView(context);
        label.setText("Scan mode");
        form.addView(label);
        Spinner mode = new Spinner(context);
        mode.setAdapter(
                new ArrayAdapter<>(
                        context,
                        android.R.layout.simple_spinner_dropdown_item,
                        new String[] {"Fast", "Complete"}));
        mode.setSelection(current.mode == ScanPlan.Mode.FAST ? 0 : 1);
        form.addView(mode);
        EditText ports =
                field(
                        context,
                        form,
                        "TCP ports (comma-separated or ranges)",
                        current.ports,
                        R.id.ports);
        EditText timeout =
                field(
                        context,
                        form,
                        "Connection timeout (100–3000 ms)",
                        Integer.toString(current.timeoutMs),
                        R.id.timeout);
        timeout.setInputType(InputType.TYPE_CLASS_NUMBER);
        CheckBox adaptive = new CheckBox(context);
        adaptive.setText("Adaptive scan (prioritize responders)");
        adaptive.setChecked(current.adaptive);
        form.addView(adaptive);\n        CheckBox nmap = new CheckBox(context);\n        nmap.setText("Nmap service detection");\n        nmap.setChecked(current.nmap);\n        form.addView(nmap);
        TextView help = new TextView(context);
        help.setText(
                "Complete mode uses more default ports, retries and longer device discovery. Custom"
                    + " ports are kept.");
        form.addView(help);
        mode.setOnItemSelectedListener(
                new AdapterView.OnItemSelectedListener() {
                    public void onNothingSelected(AdapterView<?> parent) {}

                    public void onItemSelected(
                            AdapterView<?> parent, android.view.View view, int position, long id) {
                        String current = ports.getText().toString();
                        if (current.equals(ScanPlan.FAST_PORTS)
                                || current.equals(ScanPlan.COMPLETE_PORTS))
                            ports.setText(
                                    position == 0 ? ScanPlan.FAST_PORTS : ScanPlan.COMPLETE_PORTS);
                    }
                });
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
                                            int value;
                                            try {
                                                value =
                                                        Integer.parseInt(
                                                                timeout.getText()
                                                                        .toString()
                                                                        .trim());
                                                if (value < 100 || value > 3000)
                                                    throw new IllegalArgumentException();
                                            } catch (IllegalArgumentException e) {
                                                timeout.setError("Enter 100–3000 ms");
                                                return;
                                            }
                                            String portValues = ports.getText().toString().trim();
                                            try {
                                                ScanPlan.parsePorts(portValues);
                                            } catch (IllegalArgumentException e) {
                                                ports.setError(e.getMessage());
                                                return;
                                            }
                                            ScanSettings updated =
                                                    new ScanSettings(
                                                            portValues,
                                                            value,
                                                            mode.getSelectedItemPosition() == 0
                                                                    ? ScanPlan.Mode.FAST
                                                                    : ScanPlan.Mode.COMPLETE,
                                                            adaptive.isChecked(),\n                                                            nmap.isChecked());
                                            onSave.accept(updated);
                                            dialog.dismiss();
                                        }));
        dialog.show();
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
