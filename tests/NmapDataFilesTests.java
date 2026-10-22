package com.netmap.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public final class NmapDataFilesTests {
    static Map<String,byte[]> bundle(String id,String script) {
        Map<String,byte[]> files=new LinkedHashMap<>();
        for(String name:Arrays.asList("runtime-id.txt","nse_main.lua","nmap-service-probes","scripts/script.db","nselib/stdnse.lua"))
            files.put(name,(name.equals("runtime-id.txt")?id:script).getBytes(StandardCharsets.UTF_8));
        files.put("nse-files.txt",(String.join("\n",files.keySet())+"\n").getBytes(StandardCharsets.UTF_8));
        return files;
    }
    static NmapDataFiles.Assets assets(Map<String,byte[]> files) {
        return name->{if(!files.containsKey(name))throw new IOException("Missing "+name);return new ByteArrayInputStream(files.get(name));};
    }
    static void check(boolean value,String message) {if(!value)throw new AssertionError(message);}
    static void fails(File dir,Map<String,byte[]> files) throws Exception {
        try {NmapDataFiles.install(dir,assets(files));throw new AssertionError("Invalid bundle accepted");}
        catch(IOException expected){}
    }
    public static void main(String[] args) throws Exception {
        Path temp=Files.createTempDirectory("nmap-data-tests");File parent=temp.toFile();
        try {
            Path legacy=Files.createDirectories(temp.resolve("nmap-data/scripts"));
            Files.writeString(legacy.resolve("old.nse"),"old cached script");
            Map<String,byte[]> first=bundle("a".repeat(64),"release A");
            File active=NmapDataFiles.install(parent,assets(first));
            check(!Files.exists(temp.resolve("nmap-data")),"Legacy cache was not removed");
            check(Files.readString(active.toPath().resolve("nse_main.lua")).equals("release A"),"Initial data not installed");
            NmapDataFiles.install(parent,name->{if(!name.endsWith(".txt"))throw new IOException("Unneeded recopy");return assets(first).open(name);});
            // Empty or missing files are repaired even when the runtime ID stays the same.
            Files.writeString(active.toPath().resolve("scripts/script.db"),"");
            NmapDataFiles.install(parent,assets(first));
            check(Files.size(active.toPath().resolve("scripts/script.db"))>0,"Missing data not repaired");
            Map<String,byte[]> second=bundle("b".repeat(64),"release B");
            Map<String,byte[]> incomplete=new LinkedHashMap<>(second);incomplete.remove("nselib/stdnse.lua");
            fails(parent,incomplete);
            check(active.isDirectory(),"Failed update removed previous runtime");
            check(!temp.resolve("nmap-data-"+"b".repeat(64)).toFile().exists(),"Failed runtime activated");
            File updated=NmapDataFiles.install(parent,assets(second));
            check(!active.exists(),"Previous runtime retained after successful update");
            check(Files.readString(updated.toPath().resolve("nse_main.lua")).equals("release B"),"Stale data reused");
            Path unrelated=Files.writeString(temp.resolve("keep.txt"),"user data");
            Map<String,byte[]> traversal=bundle("c".repeat(64),"bad");
            traversal.put("nse-files.txt",("../keep.txt\n"+new String(traversal.get("nse-files.txt"),StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
            fails(parent,traversal);check(Files.readString(unrelated).equals("user data"),"Traversal escaped staging");
            Map<String,byte[]> wrong=bundle("invalid","bad");fails(parent,wrong);
            // A stale cache symlink is removed without following it into another directory.
            Path outside=Files.createDirectories(temp.resolve("outside"));Files.writeString(outside.resolve("keep"),"safe");
            Files.createSymbolicLink(temp.resolve("nmap-data"),outside);
            NmapDataFiles.install(parent,assets(bundle("d".repeat(64),"release D")));
            check(Files.exists(outside.resolve("keep")),"Cache cleanup followed symlink");
            System.out.println("PASS: Nmap cache migration, reuse, repair, failed-update rollback, path validation and symlink cleanup");
        } finally {
            try(java.util.stream.Stream<Path> paths=Files.walk(temp)) {
                for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);
            }
        }
    }
}
