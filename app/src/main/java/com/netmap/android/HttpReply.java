package com.netmap.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Parses bounded HTTP response bodies, including chunked transfer framing. */
final class HttpReply {
    static byte[] body(byte[] raw,String contentType) {
        if(raw.length>65536) return new byte[0]; int split=-1;
        for(int i=0;i+3<raw.length;i++) if(raw[i]==13 && raw[i+1]==10 && raw[i+2]==13 && raw[i+3]==10) { split=i; break; }
        if(split<0 || split>8192) return new byte[0];
        String head=new String(raw,0,split,StandardCharsets.US_ASCII);
        if(!head.matches("(?s)HTTP/1\\.[01] 200\\b.*")) return new byte[0];
        Map<String,String> headers=DeviceEvidence.headers(head);
        String type=headers.getOrDefault("content-type","").split(";",2)[0].trim();
        if(!type.equalsIgnoreCase(contentType)) return new byte[0];
        byte[] body=Arrays.copyOfRange(raw,split+4,raw.length);
        try {
            if(headers.containsKey("transfer-encoding")) {
                if(!headers.get("transfer-encoding").equalsIgnoreCase("chunked")) return new byte[0];
                ByteArrayOutputStream out=new ByteArrayOutputStream(); int at=0,chunks=0;
                while(at<body.length && chunks++<512) {
                    int end=at; while(end+1<body.length && !(body[end]==13 && body[end+1]==10)) end++;
                    if(end+1>=body.length || end-at>128) return new byte[0];
                    String line=new String(body,at,end-at,StandardCharsets.US_ASCII).split(";",2)[0];
                    if(!line.matches("[0-9a-fA-F]{1,8}")) return new byte[0];
                    long size=Long.parseLong(line,16); at=end+2;
                    if(size==0) return at+1<body.length && body[at]==13 && body[at+1]==10?out.toByteArray():new byte[0];
                    if(size>body.length-at-2 || size>65536-out.size()) return new byte[0];
                    out.write(body,at,(int)size); at+=(int)size;
                    if(body[at]!=13 || body[at+1]!=10) return new byte[0]; at+=2;
                }
                return new byte[0];
            }
            if(headers.containsKey("content-length")) {
                int size=Integer.parseInt(headers.get("content-length"));
                if(size<0 || size>body.length) return new byte[0]; return Arrays.copyOf(body,size);
            }
            return body;
        } catch(RuntimeException e) { return new byte[0]; }
    }
}
