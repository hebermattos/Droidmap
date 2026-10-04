package com.netmap.android;

import java.util.*;
import java.util.regex.*;

/** Bounded, self-reported observations; never equates a port with a device model. */
public final class DeviceEvidence {
    public static final class Observation {
        public final String source, field, value;
        Observation(String source, String field, String value) { this.source=source; this.field=field; this.value=value; }
    }
    private final Map<String, List<Observation>> devices = new TreeMap<>((a,b) -> Long.compare(ScanPlan.ipv4(a), ScanPlan.ipv4(b)));
    public static final class Endpoint {
        public final int port;
        public final String source,serviceType;
        Endpoint(int port,String source,String serviceType) { this.port=port; this.source=source; this.serviceType=serviceType; }
    }
    private final Map<String,Map<Integer,Endpoint>> endpoints=new LinkedHashMap<>();
    private final Set<String> allowed;
    public synchronized void advertise(String ip,String source,String serviceType,int port) {
        if(!allowed.contains(ip) || port<1 || port>65535 || serviceType==null || !serviceType.contains("._tcp")) return;
        Map<Integer,Endpoint> perHost=endpoints.computeIfAbsent(ip,k->new LinkedHashMap<>());
        if(perHost.size()>=16 && !perHost.containsKey(port)) return;
        perHost.putIfAbsent(port,new Endpoint(port,source,clean(serviceType)));
        add(ip,source,"advertisedEndpoint",serviceType+" port "+port);
    }
    public synchronized Map<String,List<Endpoint>> endpoints() {
        Map<String,List<Endpoint>> result=new LinkedHashMap<>(); endpoints.forEach((ip,values)->result.put(ip,new ArrayList<>(values.values()))); return result;
    }
    public DeviceEvidence(Collection<String> allowed) { this.allowed = new HashSet<>(allowed); }
    public synchronized void add(String ip, String source, String field, String value) {
        if (!allowed.contains(ip) || value == null) return;
        value = clean(value);
        if (value.isEmpty()) return;
        List<Observation> list = devices.computeIfAbsent(ip, k -> new ArrayList<>());
        if (list.size() >= 48) return;
        for (Observation old : list) if (old.source.equals(source) && old.field.equals(field) && old.value.equals(value)) return;
        list.add(new Observation(source, field, value));
    }
    public synchronized List<Observation> observations(String host) { return new ArrayList<>(devices.getOrDefault(host,Collections.emptyList())); }
    public synchronized boolean hasObservations(String host) { return devices.containsKey(host); }
    public synchronized Map<String,List<Observation>> snapshot() {
        Map<String,List<Observation>> result = new LinkedHashMap<>();
        devices.forEach((ip,items) -> result.put(ip, new ArrayList<>(items))); return result;
    }
    public static String clean(String value) {
        String cleaned=value.replaceAll("[\\p{Cntrl}&&[^\\t\\n]]", "").replaceAll("\\s+", " ").trim();
        return cleaned.substring(0, Math.min(300,cleaned.length()));
    }
    public static Map<String,String> headers(String text) {
        Map<String,String> result = new LinkedHashMap<>();
        String head = text.split("\\r?\\n\\r?\\n",2)[0];
        for (String line : head.split("\\r?\\n")) {
            int split = line.indexOf(':');
            if (split > 0) result.putIfAbsent(line.substring(0,split).trim().toLowerCase(Locale.ROOT), clean(line.substring(split+1)));
        }
        return result;
    }
    public static String title(String html) {
        Matcher match = Pattern.compile("<title\\b[^>]*>(.*?)</title\\s*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(html);
        return match.find() ? clean(entities(match.group(1).replaceAll("<[^>]+>", ""))) : "";
    }
    /** Extracts simple bounded UPnP leaf fields without an XML engine or entity expansion. */
    public static Map<String,String> upnpFields(String xml) {
        Map<String,String> fields = new LinkedHashMap<>();
        if (xml.length() > 65536 || xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY")) return fields;
        Matcher match = Pattern.compile("<(friendlyName|manufacturer|modelName|modelNumber|modelDescription|serialNumber|firmwareVersion|deviceType|UDN)\\s*>([^<]{0,1000})</\\1\\s*>").matcher(xml);
        while (match.find()) fields.putIfAbsent(match.group(1), clean(entities(match.group(2))));
        return fields;
    }
    private static String entities(String value) {
        return value.replace("&lt;","<").replace("&gt;",">").replace("&quot;","\"").replace("&apos;","'").replace("&amp;","&");
    }
    public static String first(List<Observation> observations, String... fields) {
        for (String field : fields) for (Observation item : observations) if (item.field.equals(field)) return item.value;
        return "";
    }
    public static String probableType(List<Observation> observations) {
        String all = observations.stream().map(o -> o.field.equals("serviceType") || o.field.equals("deviceType") ? o.value : "").reduce("", (a,b)->a+" "+b).toLowerCase(Locale.ROOT);
        if (all.contains("_androidtvremote") || all.contains("androidtv")) return "Android TV device";
        if (all.contains("_adb")) return "Android device";
        if (all.contains("_hap")) return "HomeKit accessory";
        if (all.contains("_mqtt")) return "MQTT service device";
        if (all.contains("_rtsp")) return "Streaming media service device";
        if (all.contains("_rfb")) return "Remote desktop device";
        if (all.contains("_scanner")) return "Scanner";
        if (all.contains("_spotify-connect") || all.contains("_daap")) return "Network audio device";
        if (all.contains("_googlecast")) return "Google Cast receiver";
        if (all.contains("_ipp.") || all.contains("_ipps.") || all.contains("_printer.")) return "Printer";
        if (all.contains("_airplay")) return "AirPlay receiver";
        if (all.contains("_raop")) return "Network audio receiver";
        if (all.contains("internetgatewaydevice")) return "Router / gateway";
        if (all.contains("mediarenderer")) return "Media player / TV";
        if (all.contains("mediaserver")) return "Media server";
        if (all.contains("_smb")) return "File server / NAS";
        if (all.contains("_workstation")) return "Computer";
        return "Unknown";
    }
}
