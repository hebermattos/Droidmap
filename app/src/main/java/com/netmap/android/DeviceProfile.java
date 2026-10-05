package com.netmap.android;

import java.util.*;
import java.util.regex.Pattern;

/** Evidence-based suggestions; labels express agreement, never authenticated identity. */
final class DeviceProfile {
    final String type, manufacturer, model;
    final DeviceConfidence confidence, modelConfidence, manufacturerConfidence, typeConfidence;

    static DeviceConfidence fieldConfidence(
            List<DeviceEvidence.Observation> observations, String... fields) {
        Map<String, Set<String>> values = new HashMap<>();
        for (DeviceEvidence.Observation item : observations)
            if (Arrays.asList(fields).contains(item.field))
                values.computeIfAbsent(item.value.toLowerCase(Locale.ROOT), k -> new HashSet<>())
                        .add(item.source.split(" ", 2)[0]);
        if (values.size() > 1) return DeviceConfidence.CONFLICTING;
        if (values.isEmpty()) return DeviceConfidence.INSUFFICIENT;
        return values.values().iterator().next().size() > 1
                ? DeviceConfidence.CORROBORATED
                : DeviceConfidence.REPORTED;
    }

    final List<String> reasons;

    DeviceProfile(List<DeviceEvidence.Observation> observations) {
        Set<String> roles = new LinkedHashSet<>();
        for (DeviceEvidence.Observation item : observations) {
            String role = DeviceEvidence.probableType(Collections.singletonList(item));
            if (!role.equals("Unknown")) roles.add(role);
        }
        type =
                roles.size() > 1
                        ? "Multiple advertised roles"
                        : DeviceEvidence.probableType(observations);
        String selectedModel = DeviceEvidence.first(observations, "modelName", "modelHint");
        String maker = DeviceEvidence.first(observations, "manufacturer");
        Set<String> reportedMakers = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);

        for (DeviceEvidence.Observation item : observations) {
            if (item.field.equals("manufacturer")) reportedMakers.add(item.value);
        }
        boolean conflict = reportedMakers.size() > 1;
        if (conflict) maker = "";
        List<String> why = new ArrayList<>();
        StringBuilder clues = new StringBuilder();
        for (DeviceEvidence.Observation item : observations) {
            if (Arrays.asList(
                            "friendlyName",
                            "modelName",
                            "modelHint",
                            "manufacturer",
                            "serviceType",
                            "deviceType",
                            "httpTitle",
                            "banner",
                            "server")
                    .contains(item.field)) {
                clues.append(' ').append(item.value);
            }
            if (item.field.equals("modelName")
                    || item.field.equals("modelHint")
                    || item.field.equals("manufacturer")
                    || item.field.equals("serviceType")
                    || item.field.equals("deviceType"))
                if (why.size() < 8) why.add(item.source + ": " + item.field + "=" + item.value);
        }
        if (roles.size() > 1)
            why.add(
                    "Advertised roles: "
                            + String.join(", ", roles)
                            + "; hardware type is ambiguous.");
        if (conflict) why.add("Conflicting reported manufacturers; suggestion withheld.");
        if (maker.isEmpty() && !conflict) {
            Set<String> matches = new LinkedHashSet<>();
            for (String brand :
                    new String[] {
                        "Samsung",
                        "Sony",
                        "LG",
                        "Epson",
                        "Canon",
                        "Brother",
                        "HP",
                        "Xerox",
                        "Lexmark",
                        "Roku",
                        "Sonos",
                        "Apple",
                        "Google",
                        "TP-Link",
                        "D-Link",
                        "Netgear",
                        "MikroTik",
                        "Ubiquiti",
                        "ASUS"
                    }) {
                if (Pattern.compile("(?i)(?<![a-z0-9])" + Pattern.quote(brand) + "(?![a-z0-9])")
                        .matcher(clues)
                        .find()) matches.add(brand);
            }
            if (matches.size() == 1) {
                maker = matches.iterator().next();
                why.add(
                        "Manufacturer suggested from an explicit brand token in service metadata or"
                            + " banners.");
            } else if (matches.size() > 1)
                why.add("Conflicting brand tokens; manufacturer suggestion withheld.");
        }
        manufacturer = maker;
        modelConfidence = fieldConfidence(observations, "modelName", "modelHint");
        model = modelConfidence == DeviceConfidence.CONFLICTING ? "" : selectedModel;
        DeviceConfidence makerConfidence =
                conflict
                        ? DeviceConfidence.CONFLICTING
                        : fieldConfidence(observations, "manufacturer");
        if (!maker.isEmpty() && makerConfidence == DeviceConfidence.INSUFFICIENT)
            makerConfidence = DeviceConfidence.INFERRED;
        manufacturerConfidence = makerConfidence;
        typeConfidence =
                roles.size() > 1
                        ? DeviceConfidence.MULTIPLE_ROLES
                        : type.equals("Unknown")
                                ? DeviceConfidence.INSUFFICIENT
                                : DeviceConfidence.SERVICE_BASED;
        if (modelConfidence == DeviceConfidence.CONFLICTING)
            why.add("Conflicting reported models; suggestion withheld.");
        confidence = overallConfidence(conflict);
        reasons = Collections.unmodifiableList(why);
    }

    private DeviceConfidence overallConfidence(boolean manufacturerConflict) {
        boolean identityConflict =
                manufacturerConflict || modelConfidence == DeviceConfidence.CONFLICTING;
        boolean corroborated =
                modelConfidence == DeviceConfidence.CORROBORATED
                        || manufacturerConfidence == DeviceConfidence.CORROBORATED;
        if (!identityConflict && corroborated) return DeviceConfidence.CORROBORATED;
        if (!model.isEmpty() || !manufacturer.isEmpty())
            return DeviceConfidence.REPORTED_OR_INFERRED;
        if (!type.equals("Unknown")) return DeviceConfidence.SERVICE_BASED;
        return DeviceConfidence.INSUFFICIENT;
    }
}
