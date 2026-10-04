package com.netmap.android;

import android.content.Context;
import android.net.*;

/** Never falls back to public DNS or the default cellular resolver. */
final class WifiReverseDns {
    static DeviceIdentifier.HostnameLookup create(Context context,ScanPlan plan,DeviceEvidence evidence) {
        ConnectivityManager manager=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        try {
            for(Network network:manager.getAllNetworks()) {
                NetworkCapabilities caps=manager.getNetworkCapabilities(network);
                LinkProperties links=manager.getLinkProperties(network);
                if(caps==null || links==null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) continue;
                boolean matching=false;
                for(LinkAddress address:links.getLinkAddresses()) {
                    for(String host:plan.hosts) if(address.getAddress() instanceof java.net.Inet4Address
                        && inSubnet(address,host)) { matching=true; break; }
                    if(matching) break;
                }
                if(matching) return new ReverseDns(links.getDnsServers(),plan,evidence,new ReverseDns.SocketBinder() {
                    public void bind(java.net.DatagramSocket socket) throws java.io.IOException { network.bindSocket(socket); }
                    public void bindTcp(java.net.Socket socket) throws java.io.IOException { network.bindSocket(socket); }
                },Long.toString(network.getNetworkHandle()),null);
            }
        } catch(SecurityException ignored) { }
        return new ReverseDns(java.util.Collections.emptyList(),plan,evidence,socket -> { });
    }
    private static boolean inSubnet(LinkAddress address,String host) {
        byte[] local=address.getAddress().getAddress(); String[] parts=host.split("\\.");
        int bits=address.getPrefixLength();
        for(int i=0;i<4;i++) {
            int mask=bits>=8?255:bits<=0?0:255<<(8-bits)&255;
            if((local[i]&mask)!=(Integer.parseInt(parts[i])&mask)) return false;
            bits-=8;
        }
        return true;
    }
}
