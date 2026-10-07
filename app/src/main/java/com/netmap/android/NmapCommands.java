package com.netmap.android;

import java.util.*;
import java.util.regex.*;

/** Immutable command templates. Dynamic values are substituted into argv, never a shell. */
final class NmapCommands {
    static final class Profile {
        final List<String> argv;
        final int processTimeoutSeconds;
        Profile(List<String> argv, int timeout) {
            this.argv = tokens(argv);
            processTimeoutSeconds = bounded(timeout, 1, 300, "Process timeout");
        }
    }
    final Profile services, vulnerabilities;
    final List<String> ipv6Args, interfaceArgs;
    final Map<String, String> environment;
    final int maximumOutputBytes, outputReadTimeoutSeconds, fastLimit, completeLimit;
    final int minimumTimeoutMs, maximumTimeoutMs;
    private static final Pattern VARIABLE = Pattern.compile("\\{([A-Za-z]+)\\}");
    private static final Set<String> VARIABLES = new HashSet<>(Arrays.asList("binary", "dataDir", "libraryDir", "host", "interface", "ports", "openPorts", "timeoutMs"));

    NmapCommands(Profile services, Profile vulnerabilities, List<String> ipv6Args,
            List<String> interfaceArgs, Map<String, String> environment,
            int outputBytes, int readTimeout, int fastLimit, int completeLimit,
            int minimumTimeoutMs, int maximumTimeoutMs) {
        this.services = Objects.requireNonNull(services);
        this.vulnerabilities = Objects.requireNonNull(vulnerabilities);
        this.ipv6Args = tokens(ipv6Args);
        this.interfaceArgs = tokens(interfaceArgs);
        this.environment = Collections.unmodifiableMap(new LinkedHashMap<>(environment));
        for (Map.Entry<String, String> item : this.environment.entrySet()) {
            if (!item.getKey().matches("[A-Za-z_][A-Za-z0-9_]{0,63}"))
                throw new IllegalArgumentException("Invalid environment name");
            validateToken(item.getValue());
        }
        maximumOutputBytes = bounded(outputBytes, 1, 1048576, "Output size");
        outputReadTimeoutSeconds = bounded(readTimeout, 1, 30, "Output read timeout");
        this.fastLimit = bounded(fastLimit, 1, 256, "Fast host limit");
        this.completeLimit = bounded(completeLimit, 1, 256, "Complete host limit");
        this.minimumTimeoutMs = bounded(minimumTimeoutMs, 100, 3000, "Minimum timeout");
        this.maximumTimeoutMs = bounded(maximumTimeoutMs, minimumTimeoutMs, 3000, "Maximum timeout");
    }
    static int bounded(int value, int min, int max, String name) {
        if (value < min || value > max) throw new IllegalArgumentException(name + " must be " + min + "–" + max);
        return value;
    }
    private static List<String> tokens(List<String> values) {
        if (values.size() > 128) throw new IllegalArgumentException("Too many Nmap arguments");
        for (String value : values) validateToken(value);
        return Collections.unmodifiableList(new ArrayList<>(values));
    }
    private static void validateToken(String value) {
        if (value == null || value.isEmpty() || value.length() > 2048 || value.indexOf('\0') >= 0)
            throw new IllegalArgumentException("Invalid Nmap argument");
        Matcher matcher = VARIABLE.matcher(value);
        while (matcher.find()) if (!VARIABLES.contains(matcher.group(1)))
            throw new IllegalArgumentException("Unknown Nmap variable: " + matcher.group(1));
        if (matcher.replaceAll("").contains("{") || matcher.replaceAll("").contains("}"))
            throw new IllegalArgumentException("Invalid Nmap variable syntax");
    }
    static String expand(String template, Map<String, String> values) {
        Matcher matcher = VARIABLE.matcher(template);
        StringBuffer output = new StringBuffer();
        while (matcher.find()) {
            String value = values.get(matcher.group(1));
            if (value == null) throw new IllegalArgumentException("Missing Nmap variable: " + matcher.group(1));
            matcher.appendReplacement(output, Matcher.quoteReplacement(value));
        }
        matcher.appendTail(output);
        return output.toString();
    }
    Map<String, String> bindings(String binary, String dataDir, String host,
            Collection<Integer> ports, int timeoutMs) {
        if (binary == null || binary.trim().isEmpty() || dataDir == null || dataDir.trim().isEmpty())
            throw new IllegalArgumentException("Missing Nmap binary or data directory");
        if (ScanPlan.parseHosts(host).size() != 1) throw new IllegalArgumentException("Nmap requires one local literal IP");
        if (ports.size() > 256) throw new IllegalArgumentException("Select at most 256 ports");
        StringJoiner selected = new StringJoiner(",");
        for (Integer port : ports) {
            if (port == null || port < 1 || port > 65535) throw new IllegalArgumentException("Invalid Nmap port");
            selected.add(port.toString());
        }
        Map<String, String> values = new HashMap<>();
        values.put("binary", binary); values.put("dataDir", dataDir);
        values.put("libraryDir", new java.io.File(binary).getAbsoluteFile().getParent());
        values.put("host", ScanPlan.stripZone(host));
        String zone = IpAddresses.zoneSuffix(host);
        values.put("interface", zone.isEmpty() ? "" : zone.substring(1));
        values.put("ports", selected.toString()); values.put("openPorts", selected.toString());
        values.put("timeoutMs", Integer.toString(Math.max(minimumTimeoutMs, Math.min(maximumTimeoutMs, timeoutMs))));
        return values;
    }
    List<String> command(Profile profile, String host, Map<String, String> values) {
        List<String> command = new ArrayList<>(); command.add(values.get("binary"));
        if (ScanPlan.isIpv6(host)) for (String arg : ipv6Args) command.add(expand(arg, values));
        if (!IpAddresses.zoneSuffix(host).isEmpty()) for (String arg : interfaceArgs) command.add(expand(arg, values));
        for (String arg : profile.argv) command.add(expand(arg, values));
        return command;
    }
    Map<String, String> environment(Map<String, String> values) {
        Map<String, String> result = new LinkedHashMap<>();
        environment.forEach((key, value) -> result.put(key, expand(value, values)));
        return result;
    }
}
