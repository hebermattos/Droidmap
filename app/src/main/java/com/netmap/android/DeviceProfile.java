package com.netmap.android;

import java.util.*;
import java.util.regex.Pattern;

/** Evidence-based suggestions; labels express agreement, never authenticated identity. */
final class DeviceProfile {
    final String type,manufacturer,model,confidence;
    final List<String> reasons;
    DeviceProfile(List<DeviceEvidence.Observation> observations) {
        type=DeviceEvidence.probableType(observations);
        model=DeviceEvidence.first(observations,"modelName","modelHint");
        String maker=DeviceEvidence.first(observations,"manufacturer");
        Set<String> reportedMakers=new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        Map<String,Set<String>> agreement=new HashMap<>();
        for(DeviceEvidence.Observation item:observations) {
            if(item.field.equals("manufacturer")) reportedMakers.add(item.value);
            if(Arrays.asList("modelName","modelHint","manufacturer","friendlyName").contains(item.field))
                agreement.computeIfAbsent(item.value.toLowerCase(Locale.ROOT),k->new HashSet<>()).add(item.source.split(" ",2)[0]);
        }
        boolean conflict=reportedMakers.size()>1;
        if(conflict) maker="";
        List<String> why=new ArrayList<>(); Set<String> identitySources=new HashSet<>();
        StringBuilder clues=new StringBuilder();
        for(DeviceEvidence.Observation item:observations) {
            if(Arrays.asList("friendlyName","modelName","modelHint","manufacturer","serviceType","deviceType","httpTitle","banner","server").contains(item.field)) {
                clues.append(' ').append(item.value);
                if(!item.field.equals("serviceType") && !item.field.equals("server")) identitySources.add(item.source.split(" ",2)[0]);
            }
            if(item.field.equals("modelName") || item.field.equals("modelHint") || item.field.equals("manufacturer") || item.field.equals("serviceType") || item.field.equals("deviceType"))
                if(why.size()<8) why.add(item.source+": "+item.field+"="+item.value);
        }
        if(conflict) why.add("Conflicting reported manufacturers; suggestion withheld.");
        if(maker.isEmpty() && !conflict) {
            Set<String> matches=new LinkedHashSet<>();
            for(String brand:new String[]{"Samsung","Sony","LG","Epson","Canon","Brother","HP","Xerox","Lexmark","Roku","Sonos","Apple","Google","TP-Link","D-Link","Netgear","MikroTik","Ubiquiti","ASUS"}) {
                if(Pattern.compile("(?i)(?<![a-z0-9])"+Pattern.quote(brand)+"(?![a-z0-9])").matcher(clues).find()) matches.add(brand);
            }
            if(matches.size()==1) { maker=matches.iterator().next(); why.add("Manufacturer suggested from an explicit brand token in service metadata or banners."); }
            else if(matches.size()>1) why.add("Conflicting brand tokens; manufacturer suggestion withheld.");
        }
        manufacturer=maker;
        confidence=!conflict && agreement.values().stream().anyMatch(sources->sources.size()>=2)?"Corroborated, unverified":!model.isEmpty() || !maker.isEmpty()?"Reported or inferred, unverified":!type.equals("Unknown")?"Service-based, unverified":"Insufficient evidence";
        reasons=Collections.unmodifiableList(why);
    }
}
