#!/usr/bin/env python3
"""Generate plain-Java test input from the actual packaged JSON, without Android's JSON API."""
import json
import sys
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text())
def literal(value):
    return json.dumps(value, ensure_ascii=True)
def strings(values):
    return 'java.util.List.of(' + ','.join(map(literal, values)) + ')'
def profile(name):
    item = config['profiles'][name]
    return 'new NmapCommands.Profile(%s,%s)' % (strings(item['argv']), item['processTimeoutSeconds'])
execution = config['execution']
groups = {group['when']: group['argv'] for group in execution['conditionalArgumentGroups']}
env = 'java.util.Map.of(' + ','.join(literal(x) for pair in execution['environment'].items() for x in pair) + ')'
timeout = config['variables']['timeoutMs']
values = [profile('serviceDetection'), profile('vulnerabilityDetection'),
          strings(groups['Target is IPv6']), strings(groups['IPv6 target has an explicit interface zone']), env,
          execution['maximumOutputBytes'], execution['outputReadTimeoutSeconds'],
          config['selection']['fast']['maximumAttemptedDevices'], config['selection']['complete']['maximumAttemptedDevices'],
          timeout['minimum'], timeout['maximum']]
Path(sys.argv[2]).write_text('package com.netmap.android;\nfinal class TestNmapTemplates {\nstatic NmapCommands load(){return new NmapCommands(' + ','.join(map(str, values)) + ');}\n}\n')
