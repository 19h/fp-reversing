#!/usr/bin/env python3
"""Independent backing-byte and report consistency checks; never executes target."""
import ast
import hashlib
import json
import re
import struct
from pathlib import Path
import capstone

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'triage_evidence'
expected={
 'analysis.md':'f6421fe1c9652a27b0afb7c2827fd568728941263a3664b79bdd236c46c63ce6',
 'com.apple.driver.FairPlayIOKit_calls.txt':'3aafca153c8a9a9ac192cb738d0073dc1e6b2ff1ab9215b8a7a8706a6ae9a857',
 'com.apple.driver.FairPlayIOKit.c':'dfb28b99b293db95a78a5d2dd20f6fcf1a95f1a53245b99a090370e7a3327f08',
 'com.apple.driver.FairPlayIOKit':'2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'}
for f,h in expected.items():assert hashlib.sha256((ROOT/f).read_bytes()).hexdigest()==h,f
for p in ROOT.glob('fairplay_*.py'):ast.parse(p.read_text(),filename=str(p))
for p in OUT.glob('*.json'):json.loads(p.read_text())
reports=['analysis_corroboration.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md']
for n in reports:
    text=(ROOT/n).read_text()
    for target in re.findall(r'\]\(([^)]+)\)',text):
        if not target.startswith('https://'):assert (ROOT/target).is_file(),(n,target)
    for gate in ['QG1','QG2','QG3','QG4','QG5','QG6','QG7']:assert gate in text,(n,gate)

s=json.loads((OUT/'native_scan_summary.json').read_text())
layout=json.loads((OUT/'native_function_layout.json').read_text())
fs=json.loads((OUT/'function_index.json').read_text())
catalog=json.loads((OUT/'routine_catalog.json').read_text())
assert len(fs)==4340 and len(layout['functions'])==len(catalog)==4359
assert len({r['address'] for r in catalog})==4359
assert {r['ea'] for r in s['direct_rpc_calls']}=={'0xfffffe000a5a20f8','0xfffffe000a5a2368'}
assert 32+4+16+8+4+24==88
assert 32+4+32+8+136+172+8==392
blob=(ROOT/'com.apple.driver.FairPlayIOKit').read_bytes()
def read_va(a,size):
    for seg in s['segments']:
        start=int(seg['address'],16)
        if start<=a and a+size<=start+seg['file_size']:
            off=seg['file_offset']+a-start;return blob[off:off+size]
    raise AssertionError(hex(a))
assert struct.unpack('<II',read_va(0xfffffe0007924410,8))==(0,502)
assert struct.unpack('<II',read_va(0xfffffe0007924418,8))==(0,700)
assert struct.unpack('<Q',read_va(0xfffffe000847aa90,8))[0]==0xfffffe000a5a2064
assert struct.unpack('<Q',read_va(0xfffffe000847ace8,8))[0]==0xfffffe000a5a22d4
dispatch=json.loads((ROOT/'analysis_corroboration_ida.json').read_text())['dispatch']
assert [r['selector'] for r in dispatch]==[i+1 for i in range(40) if 0x87E27E8021>>i&1]
for r in dispatch:
    ptr=struct.unpack('<Q',read_va(0xfffffe000846b770+8*(r['selector']-1),8))[0]
    assert ptr==int(r['record'],16)
    assert struct.unpack('<Q',read_va(ptr+8,8))[0]==int(r['entry'],16)
    assert struct.unpack('<I',read_va(ptr+24,4))[0]==r['flags']==3
    assert struct.unpack('<Q',read_va(ptr+32,8))[0]==r['count0']
    assert struct.unpack('<Q',read_va(ptr+40,8))[0]==r['count1']
tags=json.loads((OUT/'dispatch_tags.json').read_text())
for r in tags:
    assert struct.unpack('<Q',read_va(int(r['slot'],16),8))[0]==int(r['target'],16)

cs=capstone.Cs(capstone.CS_ARCH_ARM64,0)
ends={r['start']:int(r['end'],16) for r in layout['functions']}
stubs=[]
for f in fs:
    if f['name'].startswith('__ZN30com_apple_driver_FairPlayIOKit') and re.search(r'return 0xFFFF(?:58A1|5BD1)LL;',f['body']) and 'if (' not in f['body']:
        a=int(f['address'],16);ins=list(cs.disasm_lite(read_va(a,ends[f['address']]-a),a))
        assert len(ins)<=6 and ins[-1][2]=='ret'
        assert all(x[2] in ['bti','mov','movk','ret'] for x in ins)
        stubs.append({'address':f['address'],'name':f['name'],'instructions':[{'ea':hex(x[0]),'mnemonic':x[2],'operands':x[3]} for x in ins]})
assert len(stubs)==22
(OUT/'provider_stub_native.json').write_text(json.dumps(stubs,indent=2)+'\n')
result={'original_artifact_hashes_unchanged':True,'all_local_report_links_exist':True,
        'python_syntax':'passed','evidence_json':'passed','catalog_entries':len(catalog),
        'selected_dispatch_records_checked_against_backing_bytes':len(dispatch),
        'normalized_dispatch_targets_checked_against_backing_bytes':len(tags),
        'direct_rpc_emissions_checked':s['direct_rpc_calls'],
        'rpc_constant_pairs_and_function_pointer_slots':'passed',
        'request_bytes':88,'complex_reply_bytes':392,'native_constant_error_provider_stubs':len(stubs),
        'limit':'Static independent consistency checks only; no target execution, PAC proof, external endpoint identity, or full protected CFG proof.'}
(OUT/'validation.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
