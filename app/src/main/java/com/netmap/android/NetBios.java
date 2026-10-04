package com.netmap.android;

import java.nio.charset.StandardCharsets;
import java.util.*;

/** NBNS node-status codec. All names and MACs are unverified server reports. */
public final class NetBios {
    public static byte[] query(int id) {
        byte[] query=new byte[50]; query[0]=(byte)(id>>>8); query[1]=(byte)id; query[5]=1; query[12]=32;
        byte[] name=new byte[16]; name[0]='*';
        for(int i=0;i<16;i++) { query[13+i*2]=(byte)('A'+((name[i]>>>4)&15)); query[14+i*2]=(byte)('A'+(name[i]&15)); }
        query[47]=0x21; query[49]=1; return query;
    }
    private static int u16(byte[] b,int offset) { if(offset<0 || offset+2>b.length) throw new IllegalArgumentException(); return (b[offset]&255)*256+(b[offset+1]&255); }
    private static int skipName(byte[] b,int offset) {
        for(int labels=0;labels<128;labels++) {
            if(offset>=b.length) throw new IllegalArgumentException(); int size=b[offset++]&255;
            if(size==0) return offset;
            if((size&0xc0)==0xc0) { if(offset>=b.length) throw new IllegalArgumentException(); return offset+1; }
            if(size>63 || offset+size>b.length) throw new IllegalArgumentException(); offset+=size;
        }
        throw new IllegalArgumentException();
    }
    public static Map<String,String> parse(byte[] response,int id) {
        Map<String,String> fields=new LinkedHashMap<>();
        try {
            if(response.length<12 || u16(response,0)!=(id&65535) || (u16(response,2)&0x800f)!=0x8000) return fields;
            int questions=u16(response,4),answers=u16(response,6),offset=12;
            if(questions>4 || answers>16) return fields;
            for(int i=0;i<questions;i++) { offset=skipName(response,offset)+4; if(offset>response.length) return fields; }
            for(int i=0;i<answers;i++) {
                offset=skipName(response,offset); int type=u16(response,offset),clazz=u16(response,offset+2),length=u16(response,offset+8); offset+=10;
                if(offset+length>response.length) return fields;
                if(type==0x21 && clazz==1 && length>=1) {
                    int count=response[offset]&255;
                    if(count>64 || 1+count*18>length) return fields;
                    for(int n=0;n<count;n++) {
                        int pos=offset+1+n*18,suffix=response[pos+15]&255; boolean group=(u16(response,pos+16)&0x8000)!=0;
                        String name=DeviceEvidence.clean(new String(response,pos,15,StandardCharsets.US_ASCII));
                        if(!group && !name.isEmpty() && (suffix==0 || suffix==0x20)) fields.putIfAbsent("netbiosName",name);
                        if(group && suffix==0) fields.putIfAbsent("workgroup",name);
                    }
                    int macOffset=offset+1+count*18;
                    if(macOffset+6<=offset+length) {
                        boolean nonzero=false,allFF=true; StringBuilder mac=new StringBuilder();
                        for(int n=0;n<6;n++) { int v=response[macOffset+n]&255; nonzero|=v!=0; allFF&=v==255; if(n>0) mac.append(':'); mac.append(String.format(Locale.ROOT,"%02X",v)); }
                        if(nonzero && !allFF) fields.put("reportedMac",mac.toString());
                    }
                    return fields;
                }
                offset+=length;
            }
        } catch(IllegalArgumentException e) { fields.clear(); }
        return fields;
    }
}
