package com.netmap.android;

import android.content.Context;
import android.text.InputType;
import android.view.View;
import android.widget.*;

/** Shared scan editor. Presets never overwrite the user's custom port draft. */
final class ScanOptionsEditor {
    private final ScanSettings current;
    private final RadioGroup choices;
    private final RadioButton[] buttons;
    private final EditText ports, timeout;
    private final CheckBox thorough, adaptive;
    private final LinearLayout custom, advanced;
    private final Button advancedToggle;
    private final TextView help;
    private final boolean enabled;

    ScanOptionsEditor(Context context, LinearLayout parent, ScanSettings current, boolean enabled) {
        this.current=current;
        this.enabled=enabled;
        TextView title=new TextView(context);
        title.setText("Scan type");
        parent.addView(title);
        choices=new RadioGroup(context);
        choices.setOrientation(RadioGroup.VERTICAL);
        buttons=new RadioButton[ScanSettings.Preset.values().length];
        for(ScanSettings.Preset preset:ScanSettings.Preset.values()) {
            RadioButton button=new RadioButton(context);
            button.setId(View.generateViewId());
            String label=preset==ScanSettings.Preset.QUICK?"Quick (recommended)":preset.label;
            if(preset.ports!=null)label+=" · "+ScanPlan.parsePorts(preset.ports).size()+" TCP ports";
            button.setText(label);
            button.setTextSize(14);
            button.setEnabled(enabled);
            choices.addView(button);
            buttons[preset.ordinal()]=button;
        }
        parent.addView(choices);
        help=new TextView(context);
        parent.addView(help);
        custom=new LinearLayout(context);
        custom.setOrientation(LinearLayout.VERTICAL);
        ports=field(context,custom,"TCP ports",current.ports,R.id.ports);
        ports.setHint("22,80,443,8000-8010");
        ports.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        ports.setEnabled(enabled);
        parent.addView(custom);

        advancedToggle=new Button(context);
        advancedToggle.setAllCaps(false);
        parent.addView(advancedToggle);
        advanced=new LinearLayout(context);
        advanced.setOrientation(LinearLayout.VERTICAL);
        thorough=new CheckBox(context);
        thorough.setText("Extra discovery and retries");
        thorough.setChecked(current.mode==ScanPlan.Mode.COMPLETE);
        thorough.setEnabled(enabled);
        advanced.addView(thorough);
        timeout=field(context,advanced,"Wait for each connection (100–3000 ms)",
                Integer.toString(current.timeoutMs),R.id.timeout);
        timeout.setInputType(InputType.TYPE_CLASS_NUMBER);
        timeout.setEnabled(enabled);
        adaptive=new CheckBox(context);
        adaptive.setText("Automatically adjust scan speed");
        adaptive.setChecked(current.adaptive);
        adaptive.setEnabled(enabled);
        advanced.addView(adaptive);
        parent.addView(advanced);
        showAdvanced(false);
        advancedToggle.setOnClickListener(v->showAdvanced(advanced.getVisibility()!=View.VISIBLE));
        choices.check(buttons[current.preset().ordinal()].getId());
        update();
        choices.setOnCheckedChangeListener((group,id)->update());
    }

    private ScanSettings.Preset selected() {
        for(ScanSettings.Preset preset:ScanSettings.Preset.values())
            if(buttons[preset.ordinal()].getId()==choices.getCheckedRadioButtonId())return preset;
        return current.preset();
    }

    private void update() {
        ScanSettings.Preset preset=selected();
        help.setText(preset.description);
        custom.setVisibility(preset==ScanSettings.Preset.CUSTOM?View.VISIBLE:View.GONE);
        thorough.setVisibility(preset==ScanSettings.Preset.CUSTOM?View.VISIBLE:View.GONE);
    }

    private void showAdvanced(boolean show) {
        advanced.setVisibility(show?View.VISIBLE:View.GONE);
        advancedToggle.setText(show?"− Advanced":"+ Advanced");
        advancedToggle.setContentDescription(show?"Collapse advanced scan settings":"Expand advanced scan settings");
    }

    ScanSettings read(String nmapArgs,int intensity) {
        if(!enabled)return current;
        int wait;
        try {
            wait=Integer.parseInt(timeout.getText().toString().trim());
            if(wait<100||wait>3000)throw new IllegalArgumentException();
        } catch(IllegalArgumentException error) {
            showAdvanced(true);
            timeout.setError("Enter 100–3000 ms");
            timeout.requestFocus();
            return null;
        }
        ScanSettings.Preset preset=selected();
        String selectedPorts=preset.selection(ports.getText().toString());
        try { ScanPlan.parsePorts(selectedPorts); }
        catch(IllegalArgumentException error) {
            ports.setError(error.getMessage());
            ports.requestFocus();
            return null;
        }
        return new ScanSettings(selectedPorts,wait,preset.depth(thorough.isChecked()),
                adaptive.isChecked(),current.nmap,nmapArgs,intensity);
    }

    private static EditText field(Context context,LinearLayout parent,String label,String value,int id) {
        TextView caption=new TextView(context);
        caption.setText(label);
        caption.setLabelFor(id);
        parent.addView(caption);
        EditText field=new EditText(context);
        field.setId(id);
        field.setSingleLine(true);
        field.setText(value);
        parent.addView(field);
        return field;
    }
}
