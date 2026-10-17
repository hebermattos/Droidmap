package com.netmap.android;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import java.io.IOException;
import java.util.*;

/** DNS-SD service-type enumeration (RFC 6763 section 9), without trusting packet targets. */
final class MdnsServiceTypes {
    static final int MAX_TYPES = 64;
    private static final Name OWNER = Name.fromConstantString("_services._dns-sd._udp.local.");

    static Message query() {
        Message query = Message.newQuery(Record.newRecord(OWNER, Type.PTR, DClass.IN));
        query.getHeader().unsetFlag(Flags.RD);
        return query;
    }

    static List<String> parse(byte[] wire, Message query) throws IOException {
        if (wire.length > 4096) return Collections.emptyList();
        Message response = new Message(wire);
        if (response.getHeader().getID() != query.getHeader().getID()
                || !response.getHeader().getFlag(Flags.QR)
                || response.getHeader().getOpcode() != Opcode.QUERY
                || response.getRcode() != Rcode.NOERROR
                || response.getHeader().getFlag(Flags.TC)
                || response.getSection(Section.QUESTION).size() != 1
                || !query.getQuestion().equals(response.getQuestion())) return Collections.emptyList();
        Set<String> types = new LinkedHashSet<>();
        for (Record record : response.getSection(Section.ANSWER)) {
            if (!(record instanceof PTRRecord) || !record.getName().equals(OWNER)
                    || record.getDClass() != DClass.IN || record.getTTL() == 0) continue;
            String target = ((PTRRecord) record).getTarget().toString().toLowerCase(Locale.ROOT);
            // Only local, two-label service types. Never follow a remote DNS name.
            if (target.matches("_[a-z0-9][a-z0-9-]{0,61}\\._(?:tcp|udp)\\.local\\.")) {
                types.add(target.substring(0, target.length() - "local.".length()));
                if (types.size() >= MAX_TYPES) break;
            }
        }
        return new ArrayList<>(types);
    }
}
