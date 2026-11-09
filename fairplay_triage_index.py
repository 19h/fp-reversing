#!/usr/bin/env python3
"""Index supplied decompiler evidence without treating inferred edges as proof."""
import bisect
import collections
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'triage_evidence'
OUT.mkdir(exist_ok=True)
SOURCE = ROOT / 'com.apple.driver.FairPlayIOKit.c'
text = SOURCE.read_text()
line_starts = [0] + [m.end() for m in re.finditer('\n', text)]
pattern = re.compile(r'^// --- Function: ([^\n]+) \((0x[0-9A-F]+)\) ---\n(.*?)^// --- End Function:[^\n]*', re.M | re.S)
functions = []
for m in pattern.finditer(text):
    name, address, body = m.groups()
    line = bisect.bisect_right(line_starts, m.start())
    strings = []
    for q in re.finditer(r'"(?:\\.|[^"\\])*"', body):
        strings.append({'line': bisect.bisect_right(line_starts,m.start(3)+q.start()), 'literal': q.group()})
    calls = sorted(set(re.findall(r'\b((?:sub_[0-9A-F]+|[A-Za-z_]\w*(?:::\w+)*))\s*\(', body)))
    globals_ = sorted(set(re.findall(r'\b(?:qword_|dword_|byte_|off_|unk_|xmmword_)[0-9A-F]+', body)))
    functions.append({'name': name, 'address': address.lower(), 'line': line,
                      'end_line': line + m.group().count('\n'), 'body': body,
                      'strings': strings, 'textual_calls': calls, 'globals': globals_,
                      'indirect_auth_calls': body.count('__arm64e_auth_branch_ia'),
                      'asm_transfers': re.findall(r'__asm\s*\{([^}]+)\}', body)})
by_name = {f['name']: f for f in functions}
by_address = {int(f['address'],16): f for f in functions}
by_short = collections.defaultdict(list)
for f in functions:
    head = f['body'].split('{',1)[0]
    mm = re.search(r'([A-Za-z_]\w*(?:::\w+)*)\s*\([^;]*$',head,re.S)
    if mm: by_short[mm.group(1)].append(f)
for f in functions:
    f['resolved_textual_callees'] = sorted({x['address'] for c in f['textual_calls'] for x in by_short.get(c,[])})

incoming = collections.defaultdict(list)
for f in functions:
    for a in f['resolved_textual_callees']: incoming[a].append(f['address'])
for f in functions: f['resolved_textual_callers'] = sorted(set(incoming[f['address']]))

graph = []
for lineno,line in enumerate((ROOT/'com.apple.driver.FairPlayIOKit_calls.txt').read_text().splitlines(),1):
    if ' -> ' in line:
        source, targets = line.lstrip('*').split(' -> ',1)
        for target in targets.split(', '): graph.append({'source':source,'target':target,'line':lineno})

# All original obfuscated symbols, plus unnamed IDA routines. Names are classified
# mechanically, never assigned cryptographic semantics by this index.
routine_inventory=[]
for f in functions:
    n=f['name']
    obfuscated = n.startswith('sub_') or (n.startswith('_') and not n.startswith('__') and any(c.isupper() for c in n) and not any(k in n for k in ['AES','IOMD','FPDebug','CBC','PIK','FCD','NVRAM','OSKext']))
    if n.startswith('__ZN30com_apple_driver_FairPlayIOKit'):
        z=re.match(r'__ZN30com_apple_driver_FairPlayIOKit(\d+)(.*)',n)
        method=z.group(2)[:int(z.group(1))] if z else ''
        obfuscated = method not in ['MetaClass','GetDeviceProperty','GetProductID','isJ42dDevice','KDDSSessionDongleProcessKey','KDGetReEncryptionVault','init','probe','start','stop','free','getMetaClass','gMetaClass'] and not method.startswith(('C1','C2','D0','D1','D2'))
    if obfuscated:
        routine_inventory.append({k:v for k,v in f.items() if k!='body'})

for name,obj in [('function_index.json',functions),('obfuscated_inventory.json',routine_inventory),('reference_edges.json',graph)]:
    (OUT/name).write_text(json.dumps(obj,indent=2)+'\n')
summary={'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'function_blocks':len(functions),
         'obfuscated_or_unnamed_inventory':len(routine_inventory),'reference_call_edges':len(graph),
         'strings_in_function_bodies':sum(len(f['strings']) for f in functions),
         'indirect_auth_call_expressions':sum(f['indirect_auth_calls'] for f in functions),
         'asm_transfer_blocks':sum(len(f['asm_transfers']) for f in functions),
         'method':'Textual indexing; no claim that textual references are reachable calls. O(N + (F+S) log N + E log E) time, O(N + E) storage: source size N, function count F, string count S, extracted evidence E.'}
(OUT/'index_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
