package com.netmap.android;

import java.util.*;

/** Offline, read-only HTTP coverage; each group has an explicit template allowlist. */
final class NucleiTemplates {
    static final int ALL = 7;
    static final String[] LABELS = {"File exposures", "HTTP configuration", "Diagnostic interfaces"};
    static final String[] IDS = {"exposures", "configuration", "diagnostics"};
    private static final String[][] FILES = {
        {"droidmap-git-head.yaml", "droidmap-env-exposure.yaml", "droidmap-git-config.yaml",
            "droidmap-svn-entries.yaml", "droidmap-mercurial-config.yaml", "droidmap-npmrc.yaml",
            "droidmap-wordpress-config-backup.yaml"},
        {"droidmap-security-headers.yaml", "droidmap-directory-listing.yaml", "droidmap-server-status.yaml",
            "droidmap-cors-credentials.yaml", "droidmap-docker-containers.yaml",
            "droidmap-kubernetes-namespaces.yaml", "droidmap-couchdb-databases.yaml"},
        {"droidmap-openapi.yaml", "droidmap-actuator.yaml", "droidmap-prometheus.yaml",
            "droidmap-phpinfo.yaml", "droidmap-nginx-status.yaml", "droidmap-actuator-env.yaml",
            "droidmap-jolokia-version.yaml"}
    };
    static int validate(int mask) {
        if (mask < 1 || (mask & ~ALL) != 0) throw new IllegalArgumentException("Select at least one Nuclei coverage group.");
        return mask;
    }
    static List<String> files(int mask) {
        validate(mask);
        List<String> names = new ArrayList<>();
        for (int i=0;i<FILES.length;i++) if ((mask & (1 << i)) != 0) Collections.addAll(names, FILES[i]);
        return Collections.unmodifiableList(names);
    }
    static List<String> groups(int mask) {
        validate(mask);
        List<String> ids = new ArrayList<>();
        for (int i=0;i<IDS.length;i++) if ((mask & (1 << i)) != 0) ids.add(IDS[i]);
        return Collections.unmodifiableList(ids);
    }
    static String summary(int mask) {
        return String.join(", ", groups(mask)) + " • " + files(mask).size() + " configured templates";
    }
    static String findingEvidence(String severity, String description) {
        return (severity.equals("info") || severity.equals("unknown") ? "INFORMATIONAL — " : "REVIEW: ")
                + DeviceEvidence.clean(description);
    }
}
