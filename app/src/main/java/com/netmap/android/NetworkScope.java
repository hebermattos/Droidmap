package com.netmap.android;

import android.content.Context;import android.net.*;import android.provider.Settings;

/** Conservative session scope: avoids comparing unrelated Wi-Fi networks or reboots. */
final class NetworkScope {
    static String current(Context context,ScanPlan plan){ConnectivityManager manager=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);if(manager==null)return "";try{for(Network network:manager.getAllNetworks()){NetworkCapabilities caps=manager.getNetworkCapabilities(network);LinkProperties links=manager.getLinkProperties(network);if(caps==null||links==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))continue;for(LinkAddress address:links.getLinkAddresses())for(String host:plan.hosts)if(WifiReverseDns.inSubnet(address,host)){int boot=Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1);if(boot<0)return "";return boot+"/"+network.getNetworkHandle()+"/"+address;}}}catch(SecurityException ignored){}return "";}
}