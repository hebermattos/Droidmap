package com.netmap.android;

import org.json.*;
import java.util.*;

/** JSON/UI boundary; the decoder and summary formatter are also plain-Java testable. */
final class BluetoothPresentation {
    static void enrich(JSONObject row) {
        JSONArray decoded = new JSONArray();
        JSONObject manufacturers = row.optJSONObject("manufacturerData");
        if (manufacturers != null) for (Iterator<String> keys=manufacturers.keys(); keys.hasNext();) {
            String id = keys.next();
            JSONObject payload = manufacturers.optJSONObject(id);
            if (payload == null) continue;
            try {
                var result = BluetoothVendorDecoder.decode(Integer.decode(id), payload.optString("hex"), row.optString("address"));
                JSONArray fields = new JSONArray();
                for (var field : result.fields()) fields.put(BluetoothScanService.object("label", field.label(), "value", field.value(), "evidence", field.evidence()));
                decoded.put(BluetoothScanService.object("companyId", id, "protocol", result.protocol(), "confidence", result.confidence(),
                        "fields", fields, "unknownHex", result.unknownHex(), "note", result.note(), "source", result.source()));
            } catch (NumberFormatException ignored) { }
        }
        BluetoothScanService.put(row, "decodedAdvertisements", decoded);
        BluetoothScanService.put(row, "summary", summary(row));
    }

    static String transport(JSONObject row) {
        if (row.optBoolean("ble") && row.optBoolean("classic")) return "BLE + Classic";
        if (row.optBoolean("ble")) return "BLE";
        if (row.optBoolean("classic")) return "Classic";
        return row.optString("type", "Unknown");
    }

    static String summary(JSONObject row) {
        List<String> companies = new ArrayList<>(), protocols = new ArrayList<>();
        JSONObject manufacturers = row.optJSONObject("manufacturerData");
        if (manufacturers != null) for (Iterator<String> keys=manufacturers.keys(); keys.hasNext();) {
            String id=keys.next();
            try { companies.add(BluetoothAdvertisement.company(Integer.decode(id)) + " " + id); }
            catch (NumberFormatException ignored) { }
        }
        JSONArray decoded = row.optJSONArray("decodedAdvertisements");
        for (int i=0; decoded != null && i<decoded.length(); i++) {
            JSONObject result=decoded.optJSONObject(i); if (result == null) continue;
            protocols.add(result.optString("protocol") + " [" + result.optString("confidence") + "]");
            JSONArray fields=result.optJSONArray("fields");
            for (int j=0; fields != null && j<fields.length(); j++) {
                JSONObject f=fields.optJSONObject(j);
                if (f == null) continue;
                String label = f.optString("label");
                if (label.equals("Advertised device kind"))
                    protocols.add(f.optString("value") + " [" + f.optString("evidence") + "; declared kind, not verified hardware]");
                else if (label.equals("Candidate SDK device class") || label.equals("Candidate battery slot 1"))
                    protocols.add(label + ": " + f.optString("value") + " [inferred]");
            }
        }
        Map<String,String> information=new LinkedHashMap<>();
        JSONArray services=row.optJSONArray("gattServices");
        for (int i=0; services != null && i<services.length(); i++) {
            JSONObject service=services.optJSONObject(i); if (service == null) continue;
            JSONArray chars=service.optJSONArray("characteristics");
            for (int j=0; chars != null && j<chars.length(); j++) {
                JSONObject c=chars.optJSONObject(j); if (c == null || !c.has("value") || c.optInt("readStatus", -1)!=0) continue;
                if (!BluetoothAdvertisement.readableInfo(service.optString("uuid"), c.optString("uuid"))) continue;
                information.put(BluetoothAdvertisement.uuidName(c.optString("uuid")), c.optString("value"));
            }
        }
        String inspection = row.optString("inspectionStatus");
        JSONObject stages = row.optJSONObject("inspectionStages");
        if (stages != null) for (String key : new String[]{"sdp", "connection", "services", "reads"}) {
            JSONObject stage = stages.optJSONObject(key);
            if (stage != null && (stage.optString("status").equals("running") || stage.optString("status").equals("retrying"))) {
                inspection = stage.optString("detail", inspection); break;
            }
        }
        JSONArray attempts=row.optJSONArray("connectionAttempts");
        return BluetoothDeviceSummary.render(new BluetoothDeviceSummary.Device(row.optString("name"), row.optString("address"), transport(row),
                row.optInt("observations")>0, row.has("rssi") ? row.optInt("rssi") : null,
                row.has("connectable") ? row.optBoolean("connectable") : null, companies, protocols, information,
                services == null ? -1 : services.length(), inspection, attempts == null ? 0 : attempts.length()));
    }

    static String decodedDetails(JSONObject row) {
        StringBuilder text=new StringBuilder();
        JSONArray decoded=row.optJSONArray("decodedAdvertisements");
        for (int i=0; decoded != null && i<decoded.length(); i++) {
            JSONObject result=decoded.optJSONObject(i); if(result==null)continue;
            text.append(result.optString("protocol")).append(" [").append(result.optString("confidence")).append("]\n");
            JSONArray fields=result.optJSONArray("fields");
            for(int j=0; fields != null && j<fields.length(); j++) {
                JSONObject f=fields.optJSONObject(j); if(f==null)continue;
                text.append(f.optString("label")).append(": ").append(f.optString("value")).append(" [").append(f.optString("evidence")).append("]\n");
            }
            text.append(result.optString("note")).append('\n');
            if(!result.optString("source").isEmpty())text.append("Source: ").append(result.optString("source")).append('\n');
            text.append("Undecoded bytes: ").append(result.optString("unknownHex")).append("\n\n");
        }
        return text.toString();
    }
}
