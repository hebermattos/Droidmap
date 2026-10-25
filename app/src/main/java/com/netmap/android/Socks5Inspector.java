package com.netmap.android;

import java.io.*;
import java.net.*;
import java.util.function.BooleanSupplier;

/** Read-only SOCKS5 method negotiation; does not request proxy forwarding. */
final class Socks5Inspector {
    private Socks5Inspector() {}
    static String classify(int version,int method) {
        if(version!=5)return "Unknown protocol (not a SOCKS5 method reply)";
        if(method==0)return "SOCKS5 no-auth method offered; forwarding NOT verified (potential exposure)";
        if(method==2)return "SOCKS5 username/password authentication requested";
        if(method==255)return "SOCKS5 no acceptable authentication methods";
        return "SOCKS5 other authentication method: "+method;
    }
    static String inspect(String host,int port,int timeoutMs,BooleanSupplier cancelled)throws IOException {
        if(cancelled.getAsBoolean())return "Skipped (cancelled)";
        int bounded=Math.min(3000,Math.max(500,timeoutMs));
        Socket socket=new Socket();
        try {
            socket.connect(new InetSocketAddress(host,port),bounded);
            socket.setSoTimeout(bounded);
            if(cancelled.getAsBoolean())return "Skipped (cancelled)";
            OutputStream output=socket.getOutputStream();
            // VER=5, one method, no-auth. No CONNECT request follows.
            output.write(new byte[]{5,1,0});output.flush();
            InputStream input=socket.getInputStream();
            int ver=input.read(),method=input.read();
            if(ver<0||method<0)return "Protocol closed during SOCKS5 negotiation; inconclusive";
            return classify(ver,method);
        } finally {socket.close();}
    }
}
