"""Decode a pprof profile (gzipped or raw protobuf) into folded stacks: `root;...;leaf count`.

Usage: pprof_fold.py <profile.pb> > out.folded
"""
import gzip, sys
from collections import defaultdict

def varint(buf, i):
    shift = value = 0
    while True:
        byte = buf[i]; i += 1
        value |= (byte & 0x7F) << shift; shift += 7
        if byte < 0x80:
            return value, i

def fields(buf):
    i = 0
    while i < len(buf):
        key, i = varint(buf, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, i = varint(buf, i)
        elif wire == 2:
            length, i = varint(buf, i)
            value = buf[i:i + length]; i += length
        elif wire == 1:
            value = buf[i:i + 8]; i += 8
        elif wire == 5:
            value = buf[i:i + 4]; i += 4
        else:
            raise ValueError(f"wire type {wire}")
        yield field, wire, value

def packed(wire, value):
    if wire == 0:
        return [value]
    out, i = [], 0
    while i < len(value):
        v, i = varint(value, i); out.append(v)
    return out

data = open(sys.argv[1], 'rb').read()
if data[:2] == b'\x1f\x8b':
    data = gzip.decompress(data)
strings, functions, locations, samples = [], {}, {}, []
for field, wire, value in fields(data):
    if field == 6:
        strings.append(value.decode('utf-8', 'replace'))
    elif field == 5:
        f = dict((k, v) for k, _, v in fields(value)); functions[f.get(1, 0)] = f.get(2, 0)
    elif field == 4:
        loc_id, lines = 0, []
        for k, w, v in fields(value):
            if k == 1: loc_id = v
            elif k == 4:
                line = dict((kk, vv) for kk, _, vv in fields(v)); lines.append(line.get(1, 0))
        locations[loc_id] = lines
    elif field == 2:
        ids, vals = [], []
        for k, w, v in fields(value):
            if k == 1: ids += packed(w, v)
            elif k == 2: vals += packed(w, v)
        samples.append((ids, vals))
folded = defaultdict(int)
for ids, vals in samples:
    frames = []
    for loc in reversed(ids):  # pprof lists the leaf first
        for fn in reversed(locations.get(loc, [])):  # and the innermost inlined frame first
            frames.append(strings[functions.get(fn, 0)] or '?')
    folded[';'.join(frames)] += vals[0] if vals else 0
for stack, count in sorted(folded.items()):
    if count:
        print(f"{stack} {count}")
