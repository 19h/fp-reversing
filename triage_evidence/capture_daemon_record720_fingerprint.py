#!/usr/bin/env python3
"""Source/IDB contracts for the allocation-to-root-fingerprint convergence.
O(source bytes + 256 * bank rules) time/output. Read-only target/IDB access.
"""
import hashlib,json
from daemon_receive_tools import ROOT,SOURCE,IMAGE,POOL,TABLE,selected
from capture_daemon_record720 import sha
from recover_daemon_descriptor_producers import verify_used_fixups

SPECS=[('root_callback',0x10040f7a4,0x10040fab4),
 ('digest_initializer',0x10045c4f0,0x10045c61c),
 ('context_allocation',0x1004b8944,0x1004b89c8),
 ('context_attachment',0x1004ab0d8,0x1004ab0e8),
 ('digest_writer',0x1000c6970,0x1000c6a70),
 ('callback_result',0x100478ef8,0x100478f58)]

def capture():
    spans=[{'label':n,'start':hex(a),'end':hex(z),'bytes_hex':IMAGE.read(a,z-a).hex(),'sha256':hashlib.sha256(IMAGE.read(a,z-a)).hexdigest()}for n,a,z in SPECS]
    raw=json.loads((ROOT/'daemon_record720_fingerprint_ida.json').read_text());assert not raw.get('isError')
    text=raw['content'][0]['text'];body=text.split('[assist:tool-output]',1)[1].split('[/assist:tool-output]',1)[0].strip();rows=json.loads(body)['results'];assert len(rows)==5
    live=[]
    for r in rows:
        a=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert len(b)==784 and IMAGE.read(a,len(b))==b
        live.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'raw_identical':True})
    rules=[('callback_state_cell',0x100fc4130,0x101031ea0,0xbb,0xfc1,POOL,0xffffffffe865c77a),
      ('shared_state_cell',0x100fc4130,0x101031ea0,0x4e,-0x6b,POOL,0xffffffffec9e1772),
      ('initializer_call',0x100fc4130,0x101031ea0,0xbb,0xcb95,TABLE,0),
      ('dispatch_base',0x100e99a00,0x100f4e390,0x6d,0x84a,POOL,0xffffffffd0c4d1ee)]
    banks=[{'label':n,**selected(*v)}for n,*v in rules]
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
      'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_fingerprint_ida.json','daemon_record720_release_replay.py','replay_daemon_record720_release.py','rpc502_certificate_contracts.json','rpc502_certificate_profiles.json','rpc502_certificate_checks.json']},
      'spans':spans,'live_IDB_matches':live,'exhaustive_banks':banks,
      'original_fixups':verify_used_fixups([int(r['slot'],16)for r in banks]),
      'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}

if __name__=='__main__':
    p=capture();(ROOT/'daemon_record720_fingerprint_source.json').write_text(json.dumps(p,indent=2)+'\n');print(json.dumps({'spans':len(p['spans']),'banks':len(p['exhaustive_banks']),'live_IDB_bytes':sum(r['size_bytes']for r in p['live_IDB_matches'])}))
