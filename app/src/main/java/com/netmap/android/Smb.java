package com.netmap.android;

import java.nio.*;
import java.util.*;

/** SMB2 NEGOTIATE only: no session setup, credentials, shares or file operations. */
final class Smb {
    static byte[] request() {
        ByteBuffer packet=ByteBuffer.allocate(112).order(ByteOrder.LITTLE_ENDIAN);
        packet.putInt(0x6c000000); // Direct TCP length: 108 bytes.
        packet.put(new byte[]{(byte)0xfe,'S','M','B'});packet.putShort((short)64);packet.putShort((short)1);
        packet.putInt(0);packet.putShort((short)0);packet.putShort((short)1);packet.putInt(0);packet.putInt(0);packet.putLong(0);
        packet.position(68);packet.putShort((short)36);packet.putShort((short)4);packet.putShort((short)1);packet.putShort((short)0);packet.putInt(0);
        UUID client=UUID.randomUUID();packet.putLong(client.getMostSignificantBits());packet.putLong(client.getLeastSignificantBits());packet.putLong(0);
        for(int dialect:new int[]{0x0202,0x0210,0x0300,0x0302}) packet.putShort((short)dialect);
        return packet.array();
    }
    static Map<String,String> parse(byte[] raw) {
        Map<String,String> result=new LinkedHashMap<>();
        if(raw.length<132 || raw.length>65536 || raw[0]!=0) return result;
        int size=((raw[1]&255)<<16)|((raw[2]&255)<<8)|(raw[3]&255);
        if(size<128 || size>raw.length-4) return result;
        ByteBuffer b=ByteBuffer.wrap(raw,4,size).slice().order(ByteOrder.LITTLE_ENDIAN);
        if(b.getInt(0)!=0x424d53fe || b.getShort(4)!=64 || b.getInt(8)!=0 || b.getShort(12)!=0
            || (b.getInt(16)&1)==0 || b.getInt(20)!=0 || b.getLong(24)!=0 || b.getShort(64)!=65) return result;
        int dialect=b.getShort(68)&65535,security=b.getShort(66)&65535;
        String version=dialect==0x0202?"2.0.2":dialect==0x0210?"2.1":dialect==0x0300?"3.0":dialect==0x0302?"3.0.2":null;
        if(version==null || (security&~3)!=0) return result;
        int offset=b.getShort(120)&65535,length=b.getShort(122)&65535;
        if(length>0 && (offset<128 || offset>size-length)) return result;
        result.put("serviceType","_smb._tcp.");result.put("smbNegotiatedDialect",version);
        result.put("smbSigning",(security&2)!=0?"Required":(security&1)!=0?"Supported":"Not advertised");
        return result;
    }
}
