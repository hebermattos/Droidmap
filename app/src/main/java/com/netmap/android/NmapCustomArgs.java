package com.netmap.android;

import java.util.*;

/** Parses user-supplied Nmap global tuning flags without allowing target, port, output or NSE overrides. */
final class NmapCustomArgs {
    private static final Set<String> FLAGS=new HashSet<>(Arrays.asList("-n","--reason","--version-light","-v","-vv"));
    private static final Set<String> VALUE_OPTIONS=new HashSet<>(Arrays.asList(
            "--max-retries","--host-timeout","--max-rtt-timeout","--min-rtt-timeout",
            "--initial-rtt-timeout","--scan-delay","--max-scan-delay","--version-intensity"));
    private NmapCustomArgs(){}

    static List<String> parse(String input) {
        if(input==null||input.trim().isEmpty())return Collections.emptyList();
        String[] raw=input.trim().split("\\s+");
        if(raw.length>24)throw new IllegalArgumentException("Use at most 24 custom Nmap arguments.");
        List<String> result=new ArrayList<>();
        for(int i=0;i<raw.length;i++) {
            String token=raw[i];
            if(FLAGS.contains(token)||token.matches("-T[0-5]")) {result.add(token);continue;}
            String option=token,value=null;
            int equals=token.indexOf('=');
            if(equals>0){option=token.substring(0,equals);value=token.substring(equals+1);}
            if(!VALUE_OPTIONS.contains(option))
                throw new IllegalArgumentException("Unsupported Nmap option: "+token+". Ports, targets, output and NSE scripts are managed by Droidmap.");
            if(value==null){if(++i>=raw.length)throw new IllegalArgumentException("Missing value for "+option);value=raw[i];}
            validateValue(option,value);result.add(option);result.add(value);
        }
        return Collections.unmodifiableList(result);
    }
    private static void validateValue(String option,String value) {
        if(value.length()>32||!value.matches("[A-Za-z0-9.]+"))
            throw new IllegalArgumentException("Invalid value for "+option);
        if(option.equals("--version-intensity")) {
            int n;try{n=Integer.parseInt(value);}catch(NumberFormatException e){throw new IllegalArgumentException("Version intensity must be 0–9.");}
            if(n<0||n>9)throw new IllegalArgumentException("Version intensity must be 0–9.");
        } else if(option.equals("--max-retries")) {
            int n;try{n=Integer.parseInt(value);}catch(NumberFormatException e){throw new IllegalArgumentException("Max retries must be 0–10.");}
            if(n<0||n>10)throw new IllegalArgumentException("Max retries must be 0–10.");
        } else if(!value.matches("[0-9]+(?:ms|s|m)?"))
            throw new IllegalArgumentException("Timing value for "+option+" must use ms, s or m.");
    }
}
