#!/usr/bin/env python3
"""Original arena split, payload-pointer publication and seed consumer demand.

Frozen caller and runtime-controller premises remain inherited. Three arena
metadata fields use one snapshot: inherited header, separate marker and ledger.
No continuous initializer/caller or native epoch is inferred. Payload bytes
retain the parent's original descending-fill provenance. One defined payload
word is consumed, then execution stops before the next state-mixing iteration.
O(parent receipts+cases*(visits+effects)) time/space. No native API/IPC,
allocation/free, concurrency, hardware PAC or IDB mutation executes.
"""
import json,struct,zlib,base64
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_callback_revisit import snapshot_read
import recover_daemon_readiness_arena as Parent

P='daemon_arena_split';ENTRY=0x100b6a918;STOP=0x100a0769c
NEXT=0x1009c46dc
H=Parent.H;M=Parent.M;N=Parent.N;MARKER=H+86620;LEDGER=Parent.D+40
BLOCK=MARKER-88;PAYLOAD=BLOCK+24
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_readiness_arena.py',
      'daemon_readiness_arena_checks.json','daemon_readiness_arena_audit.json',
      'recover_daemon_context_lock_use.py','recover_daemon_context_unseal.py',
      'daemon_context_lock_snapshot.json','daemon_context_lock_success.json',
      'recover_daemon_context_state_publish.py','daemon_context_state_publish_checks.json',
      'recover_daemon_clock_record.py','daemon_clock_record_checks.json','daemon_clock_record_audit.json',
      'audit_daemon_readiness_arena.py','audit_daemon_clock_record.py','audit_daemon_context_state_publish.py',
      'recover_daemon_return_bank_origins.py']

def snapshot_fields():
    s=json.loads(read(ROOT/'daemon_context_lock_snapshot.json'))
    mask=zlib.decompress(base64.b64decode(s['heap_owner']['known_mask_zlib_base64']))
    assert mask[86620:86628]==bytes([1])*8 and all(s['image_known_overrides'][hex(LEDGER+j)] for j in range(8))
    head=snapshot_read(s,H+8,8);marker=snapshot_read(s,MARKER,8);ledger=snapshot_read(s,LEDGER,8)
    assert head==marker==struct.pack('<Q',M+86620)
    trace=json.loads(zlib.decompress(base64.b64decode(json.loads(read(ROOT/'daemon_context_lock_success.json'))['case']['payload_zlib_base64'])))
    for step in trace['steps']:
        assert IMAGE.read(int(step['pc'],16),4).hex()==step['bytes_hex']
        for ev in step['events']:
            if ev['kind']=='write':
                a=int(ev['address'],16);n=ev['size_bytes']
                assert all(not(a<lo+width and lo<a+n) for lo,width in [(H+8,8),(MARKER,8),(LEDGER,8)])
    return [{'address':hex(a),'bytes_hex':raw.hex(),'provenance':'separate_source_defined_constructor_snapshot_arena_metadata'}
            for a,raw in [(H+8,head),(MARKER,marker),(LEDGER,ledger)]]

def marker_case(index,parent,defined):
    before=parent['intervals'][-1];v=Parent.Parent.Parent.restore(before);fields=snapshot_fields()
    assert parent['header_epoch']=='constructor_snapshot'
    effects=[fields[2]]
    v.image_fixture(LEDGER,bytes.fromhex(fields[2]['bytes_hex']),fields[2]['provenance'])
    if defined:
        f=fields[1];v.foreign_fixture(MARKER,bytes.fromhex(f['bytes_hex']),f['provenance']);effects.append(f)
    v.cut_stops=set();r=v.interval(ENTRY,'original_snapshot_marker_consumer_and_arena_split')
    assert r['boundary']['pc']==hex(Parent.Parent.ARC if defined else ENTRY)
    if not defined:assert r['boundary']['kind']=='before_undefined_foreign_owner_read' and not r['source_visits']
    else:assert r['boundary']['detail']['symbol']=='libSystem/_arc4random'
    return {'parent_header_case_index':index,'marker_defined':defined,'effects':effects,'intervals':[r],
            'payload_address':hex(PAYLOAD),'payload_extent_bytes':64,'payload_bytes_supplied':0}

def seed_case(index,parent,seed,pattern):
    before=parent['intervals'][-1];v=Parent.Parent.Parent.restore(before);rows=[];transitions=[]
    for pc,value in [(Parent.Parent.ARC,seed),(Parent.Parent.CLOCK,0),(0x100b4dba8,0),(0x100b4dbf8,0xffffffff)]:
        assert before['boundary']['pc']==hex(pc);effects=[]
        event=Parent.Parent.Parent.imported_return(v,before,value,pattern)
        if pc==Parent.Parent.CLOCK:
            out=int(before['boundary']['registers31'][0],16)
            assert out==int(before['boundary']['SP'],16)+0x230
            for a,raw in [(out,bytes(8)),(out+8,bytes(4))]:
                v.fixture(a,raw);effects.append({'address':hex(a),'bytes_hex':raw.hex(),'separate_clock_output_premise':True})
            event['timeval_padding_defined']=False
        v.cut_stops={STOP};r=v.interval(pc+4,'declared_random_clock_return_to_original_payload_demand')
        rows.append(r);transitions.append({'import_return':event,'effects':effects});before=r
    assert r['boundary']['pc']==hex(STOP)
    demand=r['boundary']['registers31'][10];v.cut_stops={NEXT}
    r=v.interval(STOP,'original_defined_payload_word_to_next_mix_iteration');rows.append(r)
    assert r['boundary']['pc']==hex(NEXT)
    return {'parent_marker_case_index':index,'seed_return32':hex(seed),'ABI_clobber_pattern':pattern,
            'transitions':transitions,'intervals':rows,'consumed_address':demand,
            'payload_bytes_supplied':0,'payload_bytes_read':4}

def fill_evidence(parent):
    rows=[]
    for j,c in enumerate(parent['header_cases']):
        if c['header_epoch']!='constructor_snapshot':continue
        r=c['intervals'][-1];ws=[w for w in r['source_writes'] if H<=int(w['address'],16)<H+N]
        assert len(ws)==156 and all(w['pc']=='0x100be73cc' and w['size_bytes']==1 for w in ws)
        assert [int(w['address'],16) for w in ws]==list(range(MARKER-1,MARKER-157,-1))
        payload=[w for w in ws if PAYLOAD<=int(w['address'],16)<PAYLOAD+64];assert len(payload)==64
        final={int(w['address'],16):bytes.fromhex(w['after_hex'])[0] for w in ws}
        rows.append({'parent_header_case_index':j,'fill_start':hex(MARKER-156),'fill_size_bytes':156,
                     'payload_source_writes':payload,'payload64_hex':bytes(final[PAYLOAD+k] for k in range(64)).hex()})
    return rows

def intervals(e):return [r for k in ['marker_cases','seed_cases'] for c in e[k] for r in c['intervals']]

def source():
    spans=[('marker_validation',ENTRY,0x100b6a944),('arena_split_and_accounting',0x100a77d3c,0x100a77e80),
           ('retained_continuation',0x100a860b8,0x100a860c8),('payload_return',0x100c190f4,0x100c19120),
           ('save_payload_and_release',0x100a8c054,0x100a8c07c),('payload_demand',0x100a075e0,STOP+8)]
    spans += [('descending_fill',0x100be73b0,0x100be73e4),('payload_record_update',STOP,0x100a07738)]
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]}
            for name,a,b in spans]

def build():
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')))
    selected=[(j,c) for j,c in enumerate(parent['header_cases']) if c['header_epoch']=='constructor_snapshot'];assert len(selected)==4
    markers=[marker_case(j,c,defined) for j,c in selected for defined in [False,True]]
    seeds=[seed_case(j,c,seed,j//4) for j,c in enumerate(markers) if c['marker_defined'] for seed in [0,0xffffffff]]
    e={'snapshot_fields':snapshot_fields(),'fill_evidence':fill_evidence(parent),'marker_cases':markers,'seed_cases':seeds};counts=Counter()
    for r in intervals(e):counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']),source_calls=len(r['source_calls']))
    used={int(x['address'],16) for r in intervals(e) for x in r['source_reads'] if int(x['address'],16) in FIXUPS}
    e.update(scope=__doc__,generator_sha256=sha(__file__),source_sha256=sha(SOURCE),dependencies={n:sha(ROOT/n) for n in DEPS},
        source_regions=source(),source_fixups=Parent.Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used),
        verified_counts={'marker_cases':len(markers),'seed_cases':len(seeds),'intervals':len(intervals(e)),**counts},
        native_API_executed=False,native_daemon_kext_pairing_established=False,native_epoch_join_established=False,full_goal_complete=False)
    return e

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
