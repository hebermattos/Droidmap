#!/usr/bin/env python3
"""Build the offline registry from IEEE CSVs (no device addresses are uploaded).

Usage: python3 tools/update-mac-vendors.py /path/to/csv-directory
Download oui.csv, mam.csv and oui36.csv from the URLs below first.
"""
import csv
import hashlib
import pathlib
import re
import sys
from datetime import date

sources = [
    ("oui.csv", "https://standards-oui.ieee.org/oui/oui.csv", 6),
    ("mam.csv", "https://standards-oui.ieee.org/oui28/mam.csv", 7),
    ("oui36.csv", "https://standards-oui.ieee.org/oui36/oui36.csv", 9),
]
directory = pathlib.Path(sys.argv[1])
entries = {}
headers = ["# IEEE MA-L / MA-M / MA-S registration owners; not verified device manufacturers.",
           "# Retrieved: " + date.today().isoformat(), "# Prefix (hex)\tOrganization"]
for filename, url, length in sources:
    data = (directory / filename).read_bytes()
    headers.append("# " + url + " SHA256=" + hashlib.sha256(data).hexdigest())
    with (directory / filename).open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) < 1000:
        raise ValueError("Incomplete IEEE registry: " + filename)
    for row in rows:
        prefix = row["Assignment"].upper()
        name = " ".join(row["Organization Name"].split())
        if not re.fullmatch(r"[0-9A-F]{%d}" % length, prefix) or not name:
            raise ValueError("Invalid IEEE entry")
        # IEEE has a few historical shared prefixes; preserve every registrant.
        entries.setdefault(prefix, set()).add(name)
output = pathlib.Path(__file__).resolve().parents[1] / "app/src/main/assets/mac-vendors.tsv"
output.write_text("\n".join(headers + [prefix + "\t" + " / ".join(sorted(names))
                                       for prefix, names in sorted(entries.items())]) + "\n", encoding="utf-8")
print("Wrote", len(entries), "prefixes to", output)
