package com.netmap.android;

import java.util.*;

public final class BluetoothPrioritiesTests {
    public static void main(String[] args) {
        String microsoft="01092022E716C78ADE59FCD7B96084E822A2F3EA85AF6CCA5E9213";
        var legacy=BluetoothVendorDecoder.decode(6,microsoft,"");
        check(legacy.protocol().equals("Microsoft CDP-like") && legacy.confidence().equals("inferred"), "legacy header remains inferred");
        check(field(legacy,"Advertised device kind").equals("Windows desktop"), "CDP device kind");
        check(field(legacy,"Advertised Nearby Share scope").equals("Own devices"), "CDP policy flag");
        check(legacy.unknownHex().equals(microsoft.substring(8)), "opaque tail remains lossless");
        var documented=BluetoothVendorDecoder.decode(6,"01292022"+microsoft.substring(8),"");
        check(documented.protocol().equals("Microsoft CDP") && documented.confidence().equals("documented"), "version one supported header");
        check(!BluetoothVendorDecoder.decode(6,"01092022","").protocol().contains("CDP"), "truncated CDP not classified");
        check(!BluetoothVendorDecoder.decode(0x75,microsoft,"").protocol().contains("CDP"), "company ID gates protocol decoder");
        check(!BluetoothVendorDecoder.decode(6,"01E92022"+microsoft.substring(8),"").protocol().equals("Microsoft CDP"), "unknown header versions not assumed");
        check(BluetoothVendorDecoder.decode(6,"030080","").protocol().equals("Microsoft Swift Pair"), "Swift Pair BLE header");
        check(!BluetoothVendorDecoder.decode(6,"030180","").protocol().equals("Microsoft Swift Pair"), "Swift Pair BR/EDR requires full fields");
        var samsung=BluetoothVendorDecoder.decode(0x75,"4204018060D003DFA83D7FD203DFA83D7E01070000000000","D0:03:DF:A8:3D:7F");
        check(field(samsung,"Observed scan address in payload").contains("byte 5"), "Samsung observed address correlation");
        check(samsung.confidence().equals("observed") && samsung.note().contains("not verified"), "Samsung model not guessed");
        var jieli=BluetoothVendorDecoder.decode(0x5d6,"000000000243357CE26133010A0000E8010000F7B397BDA85EBD26","");
        check(jieli.protocol().equals("Jieli RCSP-like") && jieli.confidence().equals("inferred"), "Jieli layout candidate");
        check(field(jieli,"Candidate SDK device class").equals("Speaker class"), "Jieli SDK device class mapping");
        check(field(jieli,"Candidate battery slot 1").equals("10%"), "Jieli candidate battery");
        check(field(jieli,"Candidate battery slot 2").startsWith("Not reported"), "zero is not asserted as empty battery");
        check(field(jieli,"Candidate RCSP address").equals("43:35:7C:E2:61:33"), "Jieli SDK address bytes");
        check(!BluetoothVendorDecoder.decode(0x5d6,"000000000243357CE26133017F0000E8010000F7B397BDA85EBD26","").protocol().equals("Jieli RCSP-like"), "invalid battery prevents structural match");
        check(BluetoothVendorDecoder.decode(0x5d6,"08004A4C414953444B","").protocol().equals("Jieli SDK tag"), "documented SDK tag");
        check(BluetoothVendorDecoder.bytes("bad").length==0 && BluetoothVendorDecoder.bytes("GG").length==0, "invalid hex bounded");
        Random random=new Random(17);
        for(int i=0;i<10000;i++) {
            byte[] data=new byte[random.nextInt(100)];random.nextBytes(data);
            BluetoothVendorDecoder.decode(new int[]{6,0x75,0x5d6}[i%3],BluetoothAdvertisement.hex(data),"00:11:22:33:44:55");
        }
        for(int status : new int[]{8,62,133,147}) {
            check(BluetoothGattRetry.eligible(1,status,false,true), "transient establishment can retry");
            check(!BluetoothGattRetry.eligible(2,status,false,true), "no third attempt");
            check(!BluetoothGattRetry.eligible(1,status,true,true), "no reconnect after established connection");
            check(!BluetoothGattRetry.eligible(1,status,false,false), "non-connectable never retried");
        }
        for(int status : new int[]{0,2,5,6,15,19,257})check(!BluetoothGattRetry.eligible(1,status,false,true), "non-transient errors not retried");
        String summary=BluetoothDeviceSummary.render(new BluetoothDeviceSummary.Device("CAR APP","43:35:7C:CD:14:CD","BLE",true,-99,true,
                List.of("Jieli"),List.of("Jieli RCSP-like [inferred]"),Map.of("Model","Example"),2,"Connection failed",2));
        check(summary.contains("weak") && summary.contains("2/2") && summary.contains("inferred") && summary.contains("GATT reported"), "summary retains evidence and result");
        check(!summary.contains("0x") && !summary.contains("metres"), "summary avoids raw payload and invented distance");
        String cached=BluetoothDeviceSummary.render(new BluetoothDeviceSummary.Device("","a","Classic",false,null,null,List.of(),List.of(),Map.of(),-1,"",0));
        check(cached.contains("not observed nearby") && !cached.contains("GATT services found"), "cached device cannot imply presence or successful GATT");
        System.out.println("PASS: Bluetooth vendor decoding, bounded retry policy and readable summaries (10,000 random payloads)");
    }
    private static String field(BluetoothVendorDecoder.Result result,String label) {
        return result.fields().stream().filter(f->f.label().equals(label)).findFirst().orElseThrow().value();
    }
    private static void check(boolean condition,String message) { if(!condition)throw new AssertionError(message); }
}
