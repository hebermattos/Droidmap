package com.netmap.android;

/** Typed inference decisions; labels remain compatible with existing reports. */
enum DeviceConfidence {
    INSUFFICIENT("Insufficient evidence"),
    CONFLICTING("Conflicting reports"),
    REPORTED("Reported, unverified"),
    CORROBORATED("Corroborated, unverified"),
    INFERRED("Inferred, unverified"),
    REPORTED_OR_INFERRED("Reported or inferred, unverified"),
    SERVICE_BASED("Service-based, unverified"),
    MULTIPLE_ROLES("Multiple service roles, unverified");

    final String label;

    DeviceConfidence(String label) {
        this.label = label;
    }
}
