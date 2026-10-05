package com.netmap.android;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/** Bounded PTR resolution, scoped TTL cache and TCP fallback on Wi-Fi only. */
class ReverseDns implements DeviceIdentifier.HostnameLookup {
    interface SocketBinder {
        void bind(DatagramSocket socket) throws IOException;
        default void bindTcp(Socket socket) throws IOException { throw new IOException("No Wi-Fi TCP binder"); }
    }
    interface Transport { byte[] exchange(Message query,InetAddress server,boolean tcp,long deadline,BooleanSupplier stopped) throws IOException; }
    static final class Answers {
        final List<String> names; final Name next; final long ttl; final boolean truncated;
        Answers(List<String> names,Name next,long ttl,boolean truncated) { this.names=names; this.next=next; this.ttl=ttl; this.truncated=truncated; }
    }
    private static final Answers EMPTY=new Answers(Collections.emptyList(),null,0,false);
    private static final class Cached { final List<String> names; final long expiry; Cached(List<String> names,long expiry) {this.names=names;this.expiry=expiry;} }
    private static final Map<String,Cached> CACHE=new LinkedHashMap<String,Cached>(512,0.75f,true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String,Cached> entry) { return size()>512; }
    };
    private final List<InetAddress> servers=new ArrayList<>();
    private final Set<String> hosts;
    private final DeviceEvidence evidence;
    private final SocketBinder binder;
    private final Transport transport;
    private final String scope;
    private final java.util.function.LongSupplier cacheClock;
    private final int timeoutMs;
    private final AtomicBoolean cancelled=new AtomicBoolean();
    private final Set<Closeable> active=ConcurrentHashMap.newKeySet();
    ReverseDns(List<InetAddress> servers,ScanPlan plan,DeviceEvidence evidence,SocketBinder binder) { this(servers,plan,evidence,binder,UUID.randomUUID().toString(),null); }
    ReverseDns(List<InetAddress> servers,ScanPlan plan,DeviceEvidence evidence,SocketBinder binder,String scope,Transport transport) {
        this(servers,plan,evidence,binder,scope,transport,System::nanoTime);
    }
    ReverseDns(List<InetAddress> servers,ScanPlan plan,DeviceEvidence evidence,SocketBinder binder,String scope,Transport transport,java.util.function.LongSupplier cacheClock) {
        this.cacheClock=cacheClock;
        for(InetAddress server:servers) if(localDns(server) && this.servers.size()<2 && !this.servers.contains(server)) this.servers.add(server);
        this.hosts=new HashSet<>(plan.hosts); this.evidence=evidence; this.binder=binder; this.scope=scope;
        this.transport=transport==null?this::exchange:transport;
        timeoutMs=plan.mode==ScanPlan.Mode.COMPLETE?1200:600;
    }
    static boolean localDns(InetAddress address) { if(address instanceof Inet6Address) return address.isLinkLocalAddress() || address.isSiteLocalAddress() || ScanPlan.isUniqueLocal(address);
        return privateIpv4(address); }
    static boolean privateIpv4(InetAddress address) {
        byte[] b=address.getAddress(); if(b.length!=4) return false;
        int first=b[0]&255,second=b[1]&255;
        return first==10 || first==172 && second>=16 && second<=31 || first==192 && second==168;
    }
    static Message query(String host) throws UnknownHostException { return query(ReverseMap.fromAddress(InetAddress.getByName(host))); }
    private static Message query(Name name) { return Message.newQuery(Record.newRecord(name,Type.PTR,DClass.IN)); }
    static List<String> names(byte[] wire,Message query) throws IOException { return answers(wire,query).names; }
    static Answers answers(byte[] wire,Message query) throws IOException {
        if(wire.length>4096) return EMPTY;
        Message response=new Message(wire); Record question=query.getQuestion();
        if(response.getHeader().getID()!=query.getHeader().getID() || !response.getHeader().getFlag(Flags.QR)
            || response.getHeader().getOpcode()!=Opcode.QUERY || response.getRcode()!=Rcode.NOERROR
            || response.getSection(Section.QUESTION).size()!=1 || !question.equals(response.getQuestion())) return EMPTY;
        if(response.getHeader().getFlag(Flags.TC)) return new Answers(Collections.emptyList(),null,0,true);
        Name owner=question.getName(); Set<Name> visited=new HashSet<>(); long ttl=3600;
        for(int depth=0;depth<=4;depth++) {
            if(!visited.add(owner)) return EMPTY;
            Set<String> names=new LinkedHashSet<>(); Name alias=null;
            for(Record record:response.getSection(Section.ANSWER)) {
                if(record.getDClass()!=DClass.IN || !record.getName().equals(owner)) continue;
                if(record instanceof PTRRecord) {
                    String name=((PTRRecord)record).getTarget().toString(true);
                    if(!name.isEmpty() && !name.equals(".")) { if(names.size()<4) names.add(name); ttl=Math.min(ttl,record.getTTL()); }
                } else if(record instanceof CNAMERecord) {
                    Name target=((CNAMERecord)record).getTarget();
                    if(alias!=null && !alias.equals(target)) return EMPTY;
                    alias=target; ttl=Math.min(ttl,record.getTTL());
                }
            }
            if(!names.isEmpty()) return alias==null?new Answers(new ArrayList<>(names),null,ttl,false):EMPTY;
            if(alias==null) return owner.equals(question.getName())?EMPTY:new Answers(Collections.emptyList(),owner,ttl,false);
            owner=alias;
        }
        return EMPTY;
    }
    @Override public void lookup(String host,long deadline,BooleanSupplier stopped) {
        if(!hosts.contains(host) || cancelled.get() || stopped.getAsBoolean() || System.nanoTime()>=deadline) return;
        for(InetAddress server:servers) {
            if(cancelled.get() || stopped.getAsBoolean()) return;
            String key=scope+"/"+server.getHostAddress()+"/"+host;
            synchronized(CACHE) {
                Cached hit=CACHE.get(key);
                if(hit!=null && cacheClock.getAsLong()<hit.expiry) { record(host,server,hit.names,true); return; }
                CACHE.remove(key);
            }
            long serverDeadline=Math.min(deadline,System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(timeoutMs));
            try {
                Message query=query(host); Set<Name> visited=new HashSet<>(); long ttl=3600;
                for(int hop=0;hop<=4 && !cancelled.get() && !stopped.getAsBoolean() && System.nanoTime()<serverDeadline;hop++) {
                    if(!visited.add(query.getQuestion().getName())) break;
                    Answers result=answers(transport.exchange(query,server,false,serverDeadline,stopped),query);
                    if(result.truncated) result=answers(transport.exchange(query,server,true,serverDeadline,stopped),query);
                    if(cancelled.get() || stopped.getAsBoolean() || System.nanoTime()>=serverDeadline) return;
                    ttl=Math.min(ttl,result.ttl);
                    if(!result.names.isEmpty()) {
                        record(host,server,result.names,false);
                        if(ttl>0) synchronized(CACHE) { CACHE.put(key,new Cached(result.names,cacheClock.getAsLong()+TimeUnit.SECONDS.toNanos(ttl))); }
                        return;
                    }
                    if(result.next==null) break;
                    query=query(result.next);
                }
            } catch(IOException | IllegalArgumentException | SecurityException ignored) { }
        }
    }
    private void record(String host,InetAddress server,List<String> names,boolean cached) {
        if(cancelled.get()) return;
        for(String name:names) evidence.add(host,"DNS PTR ("+server.getHostAddress()+")"+(cached?" TTL cache":""),"dnsHostname",name);
    }
    private int remaining(long deadline) throws SocketTimeoutException {
        long ms=TimeUnit.NANOSECONDS.toMillis(deadline-System.nanoTime());
        if(ms<=0) throw new SocketTimeoutException(); return (int)Math.min(timeoutMs,ms);
    }
    private byte[] exchange(Message query,InetAddress server,boolean tcp,long deadline,BooleanSupplier stopped) throws IOException {
        byte[] wire=query.toWire();
        if(cancelled.get() || stopped.getAsBoolean()) throw new SocketException("Cancelled");
        if(tcp) {
            try(Socket socket=new Socket()) {
                active.add(socket);
                try {
                    if(cancelled.get() || stopped.getAsBoolean()) throw new SocketException("Cancelled");
                    binder.bindTcp(socket); socket.connect(new InetSocketAddress(server,53),remaining(deadline));
                    DataOutputStream out=new DataOutputStream(socket.getOutputStream()); out.writeShort(wire.length); out.write(wire); out.flush();
                    socket.setSoTimeout(remaining(deadline)); DataInputStream in=new DataInputStream(socket.getInputStream()); int size=in.readUnsignedShort();
                    if(size<12 || size>4096) throw new IOException("DNS TCP response too large or short");
                    byte[] reply=new byte[size]; int at=0;
                    while(at<size) { socket.setSoTimeout(remaining(deadline)); int n=in.read(reply,at,size-at); if(n<0) throw new EOFException(); at+=n; }
                    return reply;
                } finally {active.remove(socket);}
            }
        }
        try(DatagramSocket socket=new DatagramSocket(null)) {
            active.add(socket);
            try {
                if(cancelled.get() || stopped.getAsBoolean()) throw new SocketException("Cancelled");
                binder.bind(socket); socket.bind(new InetSocketAddress(0)); socket.connect(server,53); socket.setSoTimeout(remaining(deadline));
                socket.send(new DatagramPacket(wire,wire.length)); byte[] buffer=new byte[4096]; DatagramPacket packet=new DatagramPacket(buffer,buffer.length); socket.receive(packet);
                return Arrays.copyOf(buffer,packet.getLength());
            } finally {active.remove(socket);}
        }
    }
    @Override public List<String> notices() { return servers.isEmpty()?Collections.singletonList("DNS PTR skipped: no matching Wi-Fi network with local DNS servers."):Collections.emptyList(); }
    @Override public void cancel() { cancelled.set(true); for(Closeable socket:active) try {socket.close();} catch(IOException ignored) { } }
}
