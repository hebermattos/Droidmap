#!/usr/bin/env python3
"""Adapt Nmap 7.992's libdnet IPv6 gateway check to Android's in6_addr macros."""
from pathlib import Path
import sys

p = Path(sys.argv[1]) / 'libdnet-stripped/src/route-linux.c'
s = p.read_text()
old = '\tif (!IN6_IS_ADDR_UNSPECIFIED(&entry->route_gw.addr_ip6)) {'
assert s.count(old) == 1, 'Pinned libdnet gateway check changed; review Android patch'
# libdnet's ip6_addr_t is not struct in6_addr. Android's IN6_* macros access
# in6_addr-specific members; copy the bytes into that actual type first.
s = s.replace(old, '''\tstruct in6_addr gateway;
\tmemcpy(&gateway, &entry->route_gw.addr_ip6, sizeof(gateway));
\tif (!IN6_IS_ADDR_UNSPECIFIED(&gateway)) {''')
p.write_text(s)
