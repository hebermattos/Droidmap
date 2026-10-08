package com.netmap.android;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Run-scoped diagnostics, separate from bounded identity evidence and report JSON. */
final class NmapOutputStore {
    static final long RUN_LIMIT=32L*1024*1024, STORAGE_LIMIT=64L*1024*1024;
    static final int FILE_LIMIT=3*1024*1024;
    private final File root,run;
    private long written;
    private int sequence;
    NmapOutputStore(File filesDir) {
        root=new File(filesDir,"nmap-output");run=new File(root,UUID.randomUUID().toString());
    }
    String save(NmapRunner.Execution result)throws IOException {
        byte[] bytes=result.text().getBytes(StandardCharsets.UTF_8);
        if(bytes.length>FILE_LIMIT||written+bytes.length>RUN_LIMIT)throw new IOException("Nmap diagnostics storage limit reached");
        if(!run.isDirectory()&&!run.mkdirs())throw new IOException("Cannot create Nmap diagnostics directory");
        prune(bytes.length);
        File file=new File(run,(++sequence)+".txt");
        try(OutputStream output=new FileOutputStream(file)){output.write(bytes);}
        written+=bytes.length;
        return run.getName()+"/"+file.getName();
    }
    private void prune(int incoming)throws IOException {
        File[] dirs=root.listFiles();if(dirs==null)throw new IOException("Cannot list Nmap diagnostics");
        Arrays.sort(dirs,Comparator.comparingLong(File::lastModified));
        long total=0;
        for(File dir:dirs){File[] files=dir.listFiles();if(files!=null)for(File file:files)total+=file.length();}
        int retained=dirs.length;
        for(File dir:dirs) {
            if(total+incoming<=STORAGE_LIMIT&&retained<=8)break;
            if(dir.equals(run))continue;
            File[] files=dir.listFiles();if(files!=null)for(File file:files){long size=file.length();if(file.delete())total-=size;}
            if(dir.delete())retained--;
        }
        if(total+incoming>STORAGE_LIMIT)throw new IOException("Nmap diagnostics storage limit reached");
    }
    static String read(File filesDir,String reference)throws IOException {
        if(!reference.matches("[a-f0-9-]{36}/[0-9]+\\.txt"))throw new IOException("Invalid Nmap output reference");
        File root=new File(filesDir,"nmap-output").getCanonicalFile();
        File file=new File(root,reference).getCanonicalFile();
        if(!file.toPath().startsWith(root.toPath()))throw new IOException("Invalid Nmap output path");
        if(!file.isFile())throw new IOException("Full output is no longer available. Run a new scan to capture it.");
        try(InputStream input=new FileInputStream(file)){return NmapRunner.readBounded(input,FILE_LIMIT);}
    }
}
