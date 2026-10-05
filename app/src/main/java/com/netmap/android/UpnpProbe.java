package com.netmap.android;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Bounded Upnp metadata lookup. */
final class UpnpProbe {
    private final ProbeContext context;

    UpnpProbe(ProbeContext context) {
        this.context = context;
    }

    void description(String host, String location) {
        try {
            URI uri = new URI(location);
            int port = uri.getPort() == -1 ? 80 : uri.getPort();
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
            byte[] response =
                    context.readBytes(
                            host,
                            port,
                            ("GET "
                                            + path
                                            + " HTTP/1.0\r\nHost: "
                                            + host
                                            + ":"
                                            + port
                                            + "\r\nConnection: close\r\n\r\n")
                                    .getBytes(StandardCharsets.US_ASCII),
                            65536);
            byte[] body = HttpReply.body(response, "text/xml");
            if (body.length == 0) body = HttpReply.body(response, "application/xml");
            for (Map.Entry<String, String> field :
                    DeviceEvidence.upnpFields(new String(body, StandardCharsets.UTF_8)).entrySet())
                context.evidence.add(host, "UPnP description", field.getKey(), field.getValue());
        } catch (URISyntaxException ignored) {
        }
    }

    static boolean allowedLocation(String location, String ip) {
        if (location == null || location.length() > 2048) return false;
        try {
            URI uri = new URI(location);
            return "http".equalsIgnoreCase(uri.getScheme())
                    && ip.equals(uri.getHost())
                    && uri.getUserInfo() == null
                    && uri.getFragment() == null
                    && (uri.getPort() == -1 || uri.getPort() > 0 && uri.getPort() <= 65535);
        } catch (URISyntaxException e) {
            return false;
        }
    }
}
