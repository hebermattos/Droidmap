package com.netmap.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

/** Runtime-specific NSE cache. Never combines new binaries with a previous release's files. */
final class NmapDataFiles {
    interface Assets { InputStream open(String name) throws IOException; }
    private NmapDataFiles() {}
    static synchronized File install(File parent,Assets assets) throws IOException {
        String id;
        try(InputStream in=assets.open("runtime-id.txt")) {
            id=new String(read(in,128),StandardCharsets.US_ASCII).trim();
        }
        if(!id.matches("[0-9a-f]{64}"))throw new IOException("Invalid Nmap runtime identity");
        List<String> names=new ArrayList<>();
        try(InputStream in=assets.open("nse-files.txt")) {
            String manifest=new String(read(in,262144),StandardCharsets.UTF_8);
            for(String name:manifest.split("\\r?\\n")) {
                if(name.isEmpty()||name.startsWith("/")||name.contains("\\")||name.contains(":")
                        ||Arrays.asList(name.split("/",-1)).stream().anyMatch(p->p.isEmpty()||p.equals("..")||p.equals("."))
                        ||name.equals(".ready")||names.contains(name)||names.size()>=4096)
                    throw new IOException("Invalid Nmap file manifest");
                names.add(name);
            }
        }
        if(!names.containsAll(Arrays.asList("runtime-id.txt","nse_main.lua","nmap-service-probes","scripts/script.db","nselib/stdnse.lua")))
            throw new IOException("Incomplete Nmap file manifest");
        File dir=new File(parent,"nmap-data-"+id);
        if(ready(dir,names,id))return dir;
        File stage=new File(parent,dir.getName()+".tmp");
        remove(stage);
        if(!stage.mkdirs())throw new IOException("Cannot create Nmap staging directory");
        try {
            long total=0;
            for(String name:names) {
                File target=new File(stage,name);
                File folder=target.getParentFile();
                if(!folder.isDirectory()&&!folder.mkdirs())throw new IOException("Cannot create Nmap subdirectory");
                try(InputStream in=assets.open(name);OutputStream out=new FileOutputStream(target)) {
                    byte[] buffer=new byte[8192];int n;long size=0;
                    while((n=in.read(buffer))!=-1) {
                        size+=n;total+=n;
                        if(size>32L*1024*1024||total>128L*1024*1024)throw new IOException("Nmap data bounds exceeded");
                        out.write(buffer,0,n);
                    }
                    if(size==0)throw new IOException("Empty Nmap runtime file: "+name);
                }
            }
            try(OutputStream out=new FileOutputStream(new File(stage,".ready"))) {
                out.write(id.getBytes(StandardCharsets.US_ASCII));
            }
            remove(dir);
            if(!stage.renameTo(dir))throw new IOException("Cannot activate Nmap runtime data");
        } finally {remove(stage);}
        // Only our legacy/versioned caches are removed, after successful activation.
        File[] old=parent.listFiles();
        if(old!=null)for(File entry:old)
            if(!entry.equals(dir)&&(entry.getName().equals("nmap-data")
                    ||entry.getName().matches("nmap-data-[0-9a-f]{64}(\\.tmp)?"))) {
                try {remove(entry);}catch(IOException ignored) { /* An unused cache must not prevent scans. */ }
            }
        return dir;
    }
    private static boolean ready(File dir,List<String> names,String id) {
        try {
            File marker=new File(dir,".ready");
            if(!marker.isFile()||marker.length()!=64)return false;
            if(!id.equals(new String(Files.readAllBytes(marker.toPath()),StandardCharsets.US_ASCII)))return false;
            for(String name:names)if(!new File(dir,name).isFile()||new File(dir,name).length()==0)return false;
            return true;
        }catch(IOException error){return false;}
    }
    private static byte[] read(InputStream in,int limit) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[4096];int n;
        while((n=in.read(buffer))!=-1) {
            if(out.size()+n>limit)throw new IOException("Nmap metadata bounds exceeded");
            out.write(buffer,0,n);
        }
        return out.toByteArray();
    }
    private static void remove(File file) throws IOException {
        if(!file.exists()&&!Files.isSymbolicLink(file.toPath()))return;
        if(file.isDirectory()&&!Files.isSymbolicLink(file.toPath())) {
            File[] children=file.listFiles();
            if(children==null)throw new IOException("Cannot list Nmap cache");
            for(File child:children)remove(child);
        }
        if(!file.delete())throw new IOException("Cannot remove stale Nmap cache");
    }
}
