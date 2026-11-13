#!/usr/bin/env python3
"""Original clock-field and random-word record composition to a strict read cut.

Frozen constructor-compatible entropy boundaries, imported return values and
explicit timeval fields remain separate premises. Output padding is undefined.
O(parent receipts+cases*(visits+effects)) time/space. No native API/IPC,
allocation/free, hardware PAC or IDB mutation executes.
"""
import json,struct
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_context_state_publish as Parent

P='daemon_clock_record';ENTRY=Parent.CLOCK+4;RANDOM2=0x100b4dba8;RANDOM3=0x100b4dbf8
STOP=0x100a0769c
PROFILES=[('failure_without_output',0xffffffff,None),('zero_time',0,(0,0)),
          ('seconds_above_u32',0,(0x100000001,999999)),('negative_seconds',0,(-1,123456)),
          ('nonzero_status_separate_defined_fields',0xffffffff,(0,0))]
PAIRS=[(0,0xffffffff),(0x89abcdef,0x76543210)]
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_context_state_publish.py',
      'daemon_context_state_publish_checks.json','daemon_context_state_publish_audit.json',
      'recover_daemon_context_lock_use.py','recover_daemon_context_unseal.py',
      'recover_daemon_return_bank_origins.py','audit_daemon_context_state_publish.py']

def clock_case(index,parent,profile):
    name,status,fields=profile;before=parent['intervals'][-1];v=Parent.Parent.restore(before)
    # The inherited row has both allocations live. Do not reconstruct a retired
    # allocation as defined merely because historical fixture bytes exist.
    assert all(any(a<=x<a+n for a,n in v.foreign_owners) for x in v.foreign_defined)
    pattern=index//4;assert pattern in [0,1]
    ev=Parent.Parent.imported_return(v,before,status,pattern);effects=[]
    out=int(before['boundary']['registers31'][0],16);sp=int(before['boundary']['SP'],16)
    assert out==sp+0x230 and before['boundary']['registers31'][1]=='0x0'
    assert not any(v.known[out-0x6800000000:out+16-0x6800000000])
    if fields is not None:
        sec,usec=fields
        for off,raw,field in [(0,struct.pack('<q',sec),'tv_sec_signed64_seconds'),(8,struct.pack('<i',usec),'tv_usec_signed32_microseconds')]:
            v.fixture(out+off,raw);effects.append({'address':hex(out+off),'bytes_hex':raw.hex(),'field':field,'separate_API_output_premise':True})
    ev['output_field_premises']=effects;ev['timeval_padding_defined']=False
    row=v.interval(ENTRY,'declared_clock_return_and_original_field_consumers')
    assert row['boundary']['pc']==hex(RANDOM2 if fields is not None else ENTRY)
    if fields is None:
        assert row['boundary']['kind']=='before_unknown_private_read' and row['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
    else:assert row['boundary']['detail']['symbol']=='libSystem/_arc4random'
    assert not any(v.known[out+12-0x6800000000:out+16-0x6800000000])
    return {'parent_entropy_case_index':index,'profile':name,'ABI_clobber_pattern':pattern,
            'clock_status32':hex(status),'clock_fields':list(fields) if fields is not None else None,
            'timeval_address':hex(out),'record_address':hex(out-16),'import_return':ev,
            'effects':effects,'intervals':[row],'native_API_executed':False}

def random_case(index,parent,pair):
    before=parent['intervals'][-1];v=Parent.Parent.restore(before);pattern=parent['ABI_clobber_pattern']
    rows=[];events=[];start=before
    for pc,value in zip([RANDOM2,RANDOM3],pair):
        assert start['boundary']['pc']==hex(pc) and start['boundary']['detail']['symbol']=='libSystem/_arc4random'
        ev=Parent.Parent.imported_return(v,start,value,pattern);ev['unsigned_random_return32']=hex(value);events.append(ev)
        v.cut_stops={STOP};row=v.interval(pc+4,'declared_random_word_and_original_record_continuation');rows.append(row);start=row
    b=rows[-1]['boundary'];assert b['pc']==hex(STOP) and b['registers31'][10]=='0x4'
    record=int(parent['record_address'],16)
    return {'parent_clock_case_index':index,'random_return_pair32':[hex(x) for x in pair],
            'import_returns':events,'intervals':rows,'record16_hex':bytes(v.u.mem_read(record,16)).hex(),
            'computed_read_address':b['registers31'][10],'computed_read_size_bytes':4,
            'native_API_executed':False}

def pointer_origin(parent):
    out=[]
    for index,c in enumerate(parent['cases']):
        if not int(c['second_pointer_return64'],16):continue
        rows=c['intervals'];hits=[]
        for ri,row in enumerate(rows):
            for j,visit in enumerate(row['source_visits']):
                if visit['pc']=='0x100a8c054':
                    f=row['source_frames'][j];sp=int(f['SP'],16)
                    assert f['registers31'][16]=='0x0'
                    ws=[w for w in row['source_writes'] if w['source_visit_index']==j]
                    assert len(ws)==1 and ws[0]['address']==hex(sp+0x190) and ws[0]['after_hex']=='00'*8
                    k=max(k for k in range(j) if row['source_visits'][k]['pc']=='0x100b73fa0')
                    assert row['source_frames'][k+1]['registers31'][16]=='0x0'
                    hits.append({'interval_index':ri,'zero_producer_visit_index':k,'pointer_store_visit_index':j,
                                 'zero_producer_pc':'0x100b73fa0','pointer_store':ws[0],
                                 'SP':hex(sp),'pointer_cell':hex(sp+0x190),
                                 'intervening_instruction_words':[v['bytes_hex'] for v in row['source_visits'][k:j+1]]})
        assert len(hits)==1;out.append({'parent_main_case_index':index,'origin':hits[0]})
    assert len(out)==4;return out

def intervals(e):return [r for c in e['clock_cases']+e['random_cases'] for r in c['intervals']]

def source():
    specs=[('clock_to_second_random',ENTRY,RANDOM2+8),('second_to_third_random',RANDOM2+4,RANDOM3+4),
           ('third_random_store',RANDOM3+4,0x100b4dc18),('zero_pointer_producer',0x100b73f98,0x100b73fa8),
           ('pointer_cell_store',0x100a8c054,0x100a8c06c),('computed_pointer',0x100a075e0,STOP+8),
           ('first_state_mix_and_less_record',0x1009c46dc,0x1009c4820),
           ('second_comparison_record',0x100b6bacc,0x100b6bb8c),
           ('less_leaf',0x100427514,0x1004275b4),('equality_or_unsigned_greater_leaf',0x100444d6c,0x100444dfc)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in specs]

def build():
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')))
    cases=[clock_case(j,c,p) for j,c in enumerate(parent['entropy_cases']) for p in PROFILES]
    random=[random_case(j,c,p) for j,c in enumerate(cases) if c['clock_fields'] is not None for p in PAIRS]
    e={'clock_cases':cases,'random_cases':random};counts=Counter()
    for r in intervals(e):counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']),source_calls=len(r['source_calls']))
    used={int(x['address'],16) for r in intervals(e) for x in r['source_reads'] if int(x['address'],16) in FIXUPS}
    e.update(scope=__doc__,generator_sha256=sha(__file__),source_sha256=sha(SOURCE),dependencies={n:sha(ROOT/n) for n in DEPS},
        source_regions=source(),source_fixups=Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used),pointer_origin_evidence=pointer_origin(parent),
        verified_counts={'clock_cases':len(cases),'random_cases':len(random),'intervals':len(intervals(e)),**counts},
        native_API_executed=False,native_daemon_kext_pairing_established=False,native_epoch_join_established=False,full_goal_complete=False)
    return e

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
