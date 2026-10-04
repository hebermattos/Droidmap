package com.netmap.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Get-Printer-Attributes only; never submits or changes a print job. */
final class Ipp {
    static final int REQUEST_ID=0x4e4d;
    static byte[] request(String uri) throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream(); DataOutputStream out=new DataOutputStream(bytes);
        out.writeShort(0x0101); out.writeShort(0x000b); out.writeInt(REQUEST_ID); out.writeByte(1);
        attribute(out,0x47,"attributes-charset","utf-8"); attribute(out,0x48,"attributes-natural-language","en");
        attribute(out,0x45,"printer-uri",uri);
        attribute(out,0x44,"requested-attributes","printer-name");
        for(String name:new String[]{"printer-info","printer-make-and-model","printer-location","printer-uuid"}) attribute(out,0x44,"",name);
        out.writeByte(3); return bytes.toByteArray();
    }
    private static void attribute(DataOutputStream out,int tag,String name,String value) throws IOException {
        byte[] n=name.getBytes(StandardCharsets.UTF_8),v=value.getBytes(StandardCharsets.UTF_8);
        out.writeByte(tag); out.writeShort(n.length); out.write(n); out.writeShort(v.length); out.write(v);
    }
    static Map<String,String> parse(byte[] data) {
        Map<String,String> fields=new LinkedHashMap<>();
        if(data.length<9 || data.length>65536) return fields;
        try {
            DataInputStream in=new DataInputStream(new ByteArrayInputStream(data)); int version=in.readUnsignedShort(),status=in.readUnsignedShort();
            if((version!=0x0100 && version!=0x0101 && version!=0x0200) || status>0xff || in.readInt()!=REQUEST_ID) return fields;
            String name=""; boolean printerGroup=false,ended=false; int attributes=0;
            while(in.available()>0 && attributes++<512) {
                int tag=in.readUnsignedByte();
                if(tag==3) { ended=true; break; }
                if(tag<=0x0f) { printerGroup=tag==4; name=""; continue; }
                int n=in.readUnsignedShort(); if(n>1024 || n>in.available()) return Collections.emptyMap();
                byte[] key=new byte[n]; in.readFully(key); if(n>0) name=new String(key,StandardCharsets.UTF_8);
                int size=in.readUnsignedShort(); if(size>in.available()) return Collections.emptyMap();
                byte[] value=new byte[size]; in.readFully(value);
                if(!printerGroup || size>1024 || (tag!=0x41 && tag!=0x42 && tag!=0x45)) continue;
                String field=name.equals("printer-name")?"friendlyName":name.equals("printer-info")?"printerInfo":name.equals("printer-make-and-model")?"modelName":name.equals("printer-location")?"location":name.equals("printer-uuid")?"deviceUuid":null;
                if(field!=null) fields.putIfAbsent(field,DeviceEvidence.clean(new String(value,StandardCharsets.UTF_8)));
            }
            return ended?fields:Collections.emptyMap();
        } catch(IOException | RuntimeException e) { return Collections.emptyMap(); }
    }
    static String resource(String value) {
        if(value==null || value.isEmpty()) return "/ipp/print";
        if(value.contains("://")) return null;
        String path=value.startsWith("/")?value:"/"+value;
        if(path.length()>512 || !path.matches("/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*") || path.contains("..") || path.contains("%")) return null;
        return path;
    }
}
