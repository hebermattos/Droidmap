package com.netmap.android;

/** TXT keys are interpreted in the context of the announcing service. */
final class MdnsFields {
    static String field(String type,String key) {
        switch(key) {
            case "fn": case "name": return "friendlyName";
            case "manufacturer": return "manufacturer";
            case "uuid": case "deviceid": return "deviceUuid";
            case "rp": return "printerResource";
            case "note": return "location";
            case "osvers": return "reportedOsVersion";
            case "product": return "reportedProduct";
            case "model": return "modelHint";
            case "md": return type.startsWith("_googlecast.")?"modelHint":"reportedMd";
            case "am": return type.startsWith("_airplay.") || type.startsWith("_raop.")?"modelHint":"reportedAm";
            case "ty": return type.startsWith("_ipp.") || type.startsWith("_ipps.") || type.startsWith("_printer.")?"modelHint":"reportedTy";
            default: return "txtAttribute";
        }
    }
}
