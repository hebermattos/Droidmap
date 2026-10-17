package com.netmap.android;

import org.junit.Test;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import java.util.*;
import static org.junit.Assert.*;

public class MdnsServiceTypesTest {
    private Message response(Message query, String... targets) {
        Message reply = new Message(query.getHeader().getID());
        reply.getHeader().setFlag(Flags.QR);
        reply.addRecord(query.getQuestion(), Section.QUESTION);
        for (String target : targets)
            reply.addRecord(new PTRRecord(query.getQuestion().getName(), DClass.IN, 120,
                    Name.fromConstantString(target)), Section.ANSWER);
        return reply;
    }

    @Test public void discoversCustomTcpAndUdpTypesWithoutDuplicates() throws Exception {
        Message query = MdnsServiceTypes.query();
        assertFalse(query.getHeader().getFlag(Flags.RD));
        Message reply = response(query, "_custom._tcp.local.", "_CUSTOM._tcp.local.", "_matter._udp.local.");
        assertEquals(Arrays.asList("_custom._tcp.", "_matter._udp."),
                MdnsServiceTypes.parse(reply.toWire(), query));
    }

    @Test public void rejectsRemoteDomainsSubtypesAndWrongOwners() throws Exception {
        Message query = MdnsServiceTypes.query();
        Message reply = response(query, "_http._tcp.example.com.", "_x._sub._http._tcp.local.",
                "_x._sctp.local.", "_http._tcp.local.");
        reply.addRecord(new PTRRecord(Name.fromConstantString("elsewhere.local."), DClass.IN, 120,
                Name.fromConstantString("_injected._tcp.local.")), Section.ANSWER);
        assertEquals(Collections.singletonList("_http._tcp."), MdnsServiceTypes.parse(reply.toWire(), query));
    }

    @Test public void rejectsMismatchedTruncatedAndNonResponsePackets() throws Exception {
        Message query = MdnsServiceTypes.query();
        Message reply = response(query, "_http._tcp.local.");
        reply.getHeader().setID((query.getHeader().getID() + 1) & 65535);
        assertTrue(MdnsServiceTypes.parse(reply.toWire(), query).isEmpty());
        reply.getHeader().setID(query.getHeader().getID());
        reply.getHeader().setFlag(Flags.TC);
        assertTrue(MdnsServiceTypes.parse(reply.toWire(), query).isEmpty());
        assertTrue(MdnsServiceTypes.parse(query.toWire(), query).isEmpty());
        assertTrue(MdnsServiceTypes.parse(new byte[4097], query).isEmpty());
        reply = response(query, "_http._tcp.local.");
        reply.removeAllRecords(Section.QUESTION);
        assertTrue(MdnsServiceTypes.parse(reply.toWire(), query).isEmpty());
    }

    @Test public void ignoresGoodbyesAndWrongClassesAndBoundsTypes() throws Exception {
        Message query = MdnsServiceTypes.query();
        Message reply = response(query);
        reply.addRecord(new PTRRecord(query.getQuestion().getName(), DClass.IN, 0,
                Name.fromConstantString("_gone._tcp.local.")), Section.ANSWER);
        reply.addRecord(new PTRRecord(query.getQuestion().getName(), DClass.CH, 120,
                Name.fromConstantString("_wrong._tcp.local.")), Section.ANSWER);
        assertTrue(MdnsServiceTypes.parse(reply.toWire(), query).isEmpty());
        for(int i=0;i<70;i++) reply.addRecord(new PTRRecord(query.getQuestion().getName(), DClass.IN,
                120, Name.fromConstantString("_s"+i+"._tcp.local.")), Section.ANSWER);
        assertEquals(64, MdnsServiceTypes.parse(reply.toWire(), query).size());
    }

    @Test(expected=java.io.IOException.class) public void rejectsMalformedPacket() throws Exception {
        MdnsServiceTypes.parse(new byte[]{1,2,3}, MdnsServiceTypes.query());
    }

    @Test public void udpAnnouncementsNeverBecomeTcpEndpoints() {
        DeviceEvidence evidence = new DeviceEvidence(Collections.singletonList("192.168.0.1"));
        evidence.advertise("192.168.0.1", "mDNS", "_matter._udp.", 5540);
        assertTrue(evidence.endpoints().isEmpty());
    }
}
