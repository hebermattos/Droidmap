#!/usr/bin/env python3
"""Apply checked compatibility and upstream NSE fixes to pinned Nmap 7.992."""
from pathlib import Path
import sys


def replace_once(source, old, new, label):
    if source.count(old) != 1:
        raise SystemExit(f'Pinned Nmap source changed; review {label}')
    return source.replace(old, new, 1)


def patch(root):
    route = root / 'libdnet-stripped/src/route-linux.c'
    nse = root / 'nse_nmaplib.cc'
    # libdnet's ip6_addr_t is not struct in6_addr. Android's IN6_* macros
    # access in6_addr-specific members; copy into that actual type first.
    route_source = replace_once(route.read_text(),
        '\tif (!IN6_IS_ADDR_UNSPECIFIED(&entry->route_gw.addr_ip6)) {',
        '\tstruct in6_addr gateway;\n'
        '\tmemcpy(&gateway, &entry->route_gw.addr_ip6, sizeof(gateway));\n'
        '\tif (!IN6_IS_ADDR_UNSPECIFIED(&gateway)) {',
        'Android libdnet gateway patch')

    # Exact backport of upstream 29cb897062d0b803e5d00fb6419b131c6fad3123:
    # https://github.com/nmap/nmap/issues/3557
    # Lazy loading no longer sets a global nmap table. Capture the registry
    # as a closure upvalue so version script rules can read script-intensity.
    nse_source = replace_once(nse.read_text(),
        '    lua_getglobal(L, "nmap");\n'
        '    lua_getfield(L, -1, "registry");\n'
        '    lua_getfield(L, -1, "args");\n'
        '    lua_getfield(L, -1, "script-intensity");\n\n'
        '    script_intensity = lua_tointegerx(L, lua_gettop(L), &is_script_intensity_set);\n\n'
        '    lua_pop(L, 4);',
        '    lua_pushvalue(L, lua_upvalueindex(1)); /* nmap.registry */\n'
        '    lua_getfield(L, -1, "args");\n'
        '    lua_getfield(L, -1, "script-intensity");\n\n'
        '    script_intensity = lua_tointegerx(L, lua_gettop(L), &is_script_intensity_set);\n\n'
        '    lua_pop(L, 3);',
        'NSE version_intensity registry lookup')
    nse_source = replace_once(nse_source,
        '  lua_newtable(L);\n'
        '  lua_setfield(L, nmap_idx, "registry");',
        '  lua_newtable(L); /* nmap.registry */\n'
        '  /* Copy nmap.registry. One copy to set nmap["registry"] */\n'
        '  lua_pushvalue(L, -1);\n'
        '  lua_setfield(L, nmap_idx, "registry");\n'
        '  /* and the other as upvalue for l_get_version_intensity. */\n'
        '  lua_pushcclosure(L, l_get_version_intensity, 1);\n'
        '  lua_setfield(L, nmap_idx, "version_intensity");',
        'NSE version_intensity closure registration')
    # Validate every expected source fragment before changing either file.
    route.write_text(route_source)
    nse.write_text(nse_source)


if __name__ == '__main__':
    patch(Path(sys.argv[1]))
