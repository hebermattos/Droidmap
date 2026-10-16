package com.netmap.android;

import java.util.*;

/** Splits user-supplied Nmap arguments into argv without applying option validation or invoking a shell. */
final class NmapCustomArgs {
    private NmapCustomArgs(){}

    static List<String> parse(String input) {
        if(input==null||input.trim().isEmpty())return Collections.emptyList();
        List<String> result=new ArrayList<>();StringBuilder token=new StringBuilder();char quote=0;boolean escaping=false;
        for(int i=0;i<input.length();i++){
            char c=input.charAt(i);
            if(escaping){token.append(c);escaping=false;continue;}
            if(c=='\\'){escaping=true;continue;}
            if(quote!=0){if(c==quote)quote=0;else token.append(c);continue;}
            if(c=='\''||c=='"'){quote=c;continue;}
            if(Character.isWhitespace(c)){if(token.length()>0){result.add(token.toString());token.setLength(0);}continue;}
            token.append(c);
        }
        if(escaping)token.append('\\');
        if(quote!=0)throw new IllegalArgumentException("Unclosed quote in Nmap parameters.");
        if(token.length()>0)result.add(token.toString());
        return Collections.unmodifiableList(result);
    }
}
