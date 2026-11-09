#!/usr/bin/env python3
"""Original callback fields, attribute workspace and atomic/readiness source.
O(source bytes + bounded pointer records) time/output; no native execution.
"""
import json,hashlib
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,qword
from capture_daemon_record720 import sha
from recover_daemon_descriptor_producers import verify_used_fixups

SPECS=[('version',0x10041f768,0x10041f838),('version_byte',0x100161bdc,0x100161c24),
 ('serial',0x10040f1d4,0x10040f30c),('serial_publication',0x1000abd5c,0x1000abda0),
 ('serial_byte',0x1000af0f8,0x1000af118),('TBS',0x10044f7a4,0x10044f7bc),
 ('OID',0x1004150f0,0x100415108),('issuer',0x100413254,0x10041326c),
 ('subject',0x10000cd38,0x10000cd50),('attribute',0x10044fdc0,0x10044fe98),
 ('attribute_gate',0x10043aa98,0x10043ab80),('name_compare',0x100610bd0,0x100610c0c),
 ('atomic',0x100503d14,0x100503d38),('readiness',0x10048d690,0x10048d6d0),
 ('ready_frame',0x100633ee8,0x100633f28)]

def capture():
    spans=[{'label':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':hashlib.sha256(IMAGE.read(a,z-a)).hexdigest()}for n,a,z in SPECS]
    raw=json.loads((ROOT/'daemon_record720_fields_ida.json').read_text());assert not raw.get('isError');body=raw['content'][0]['text'].split('[assist:tool-output]',1)[1].split('[/assist:tool-output]',1)[0].strip();rows=json.loads(body)['results'];assert len(rows)==9;live=[]
    for r in rows:
        a=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert len(b)==256 and b==IMAGE.read(a,len(b));live.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'raw_identical':True})
    literal=IMAGE.read(0x100f780d0,94);assert literal[-1]==0x11 and 0x11 not in literal[:-1]
    routes=[{'index':hex(i),'slot':hex(TABLE+i*8),'target':hex(qword(TABLE+i*8))}for i in [0x7918,0x84d1,0x54d3,0xc3cf]]
    gate=IMAGE.read(0x1010b5de0,4);assert gate.hex()=='965d0000'
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'spans':spans,'live_IDB_matches':live,'routes':routes,'original_fixups':verify_used_fixups([int(r['slot'],16)for r in routes]),'issuer_literal':{'address':'0x100f780d0','size_bytes':94,'bytes_hex':literal.hex(),'xor_key8':'0x11','decoded_ASCII_with_NUL':bytes(x^0x11 for x in literal).decode('ascii')},'atomic_word_image_initial_bytes_hex':gate.hex(),'image_initial_is_native_current_state':False,'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_fields_ida.json','daemon_record720_fingerprint_source.json','daemon_record720_fingerprint_checks.json','daemon_record720_fields_replay.py','replay_daemon_record720_fields.py']},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}

if __name__=='__main__':
    r=capture();(ROOT/'daemon_record720_fields_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'source_spans':len(r['spans']),'IDB_bytes':sum(r['size_bytes']for r in r['live_IDB_matches'])}))
