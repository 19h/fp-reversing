#!/usr/bin/env python3
"""Evaluate the recovered typed DAG without source instructions or a solver.
O(DAG nodes + edges + lookup bytes) time/space per retained context/input.
The fixed context, literal tables and certified address obligations qualify it.
"""
from functools import reduce
from operator import xor, or_, and_, mul


def transform(case, data):
    assert len(data) == 16
    g = case['graph']; nodes = g['nodes']; cache = dict(zip(g['input_nodes'], data))
    windows = {k: bytes.fromhex(v['bytes_hex']) for k, v in g['windows'].items()}
    def value(root):
        pending = [(root, False)]
        while pending:
            key, ready = pending.pop()
            if key in cache: continue
            row = nodes[key]; op, width = row[:2]
            if op in ['literal', 'bool']: cache[key] = row[2]; continue
            assert op != 'variable', ('unbound lookup/input', key, row)
            params, children = row[2:]
            if not ready:
                pending.append((key, True)); pending.extend((j, False) for j in reversed(children)); continue
            xs = [cache[j] for j in children]
            if op == 'extract': out = xs[0] >> params[1]
            elif op == 'concat':
                out = 0
                for j, x in zip(children, xs): out = (out << nodes[j][1]) | x
            elif op == 'bvnot': out = ~xs[0]
            elif op == 'bvxor': out = reduce(xor, xs)
            elif op == 'bvor': out = reduce(or_, xs)
            elif op == 'bvand': out = reduce(and_, xs)
            elif op == 'bvadd': out = sum(xs)
            elif op == 'bvmul': out = reduce(mul, xs)
            elif op == 'bvsub': out = xs[0]-xs[1]
            elif op == 'bvneg': out = -xs[0]
            elif op == 'bvshl': out = xs[0] << xs[1] if xs[1] < width else 0
            elif op == 'bvlshr': out = xs[0] >> xs[1]
            elif op == 'if': out = xs[1] if xs[0] else xs[2]
            elif op == '=': out = xs[0] == xs[1]
            elif op == 'not': out = not xs[0]
            elif op == 'or': out = any(xs)
            elif op == 'and': out = all(xs)
            elif op == 'bvule': out = xs[0] <= xs[1]
            elif op == 'bvult': out = xs[0] < xs[1]
            elif op == 'zero_extend': out = xs[0]
            else: raise AssertionError(('unsupported graph operation', op))
            cache[key] = out & ((1 << width)-1) if width else bool(out)
        return cache[root]
    accesses = []
    for r in g['lookups']:
        index = value(r['index_node']); assert 0 <= index < 256
        unit = r['unit_bytes']; start = unit*index; raw = windows[r['base']][start:start+unit]
        assert len(raw) == unit and r['value_node'] not in cache
        cache[r['value_node']] = int.from_bytes(raw, 'little')
        accesses.append({'pc': r['pc'], 'address': hex(int(r['base'], 16)+start), 'bytes_hex': raw.hex()})
    out = bytearray(16)
    for r in g['output']: out[r['offset']] = value(r['value_node'])
    return bytes(out), accesses
