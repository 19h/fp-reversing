#!/usr/bin/env python3
"""Conditional 104-byte auxiliary initializer and existing-table admission.

Two frozen caller states, two ordinary ABI clobber patterns and NULL/non-NULL
pointer returns are separate premises. Non-NULL adds an exactly 104-byte,
initially undefined owner. Separate controls replace only caller+0x100 with
zero and stop before the alternate target. Main paths stop before the first
undefined table read. O(parent bytes+cases*(visits+effects)) time/space.
No native API/IPC, allocation/free, hardware PAC or IDB mutation executes.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_context_lock_use import imported_return
from recover_daemon_context_state_publish import owner
from recover_daemon_environment_outputs import fixups
import recover_daemon_generated_stream as Parent

P='daemon_auxiliary_state';ENTRY=Parent.NEXT+4;B=0x6600005000;N=104
J=0x6500115b20;STOP=0x1008660f0;SKIP=0x100867168
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt',
      'recover_daemon_generated_stream.py','audit_daemon_generated_stream.py',
      'daemon_generated_stream_checks.json','daemon_generated_stream_audit.json',
      'recover_daemon_context_lock_use.py','recover_daemon_context_state_publish.py',
      'recover_daemon_second_mix.py','recover_daemon_context_unseal.py',
      'audit_daemon_readiness_arena.py','audit_daemon_context_state_publish.py',
      'audit_daemon_network_record.py','recover_daemon_environment_outputs.py',
      'recover_daemon_return_bank_origins.py']
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc

def pointer_return(v,before,result,pattern):
    event=imported_return(v,before,0,pattern);v.set(0,result)
    event['return_registers31'][0]=hex(result)
    event.pop('return32');event.pop('int_return_upper32_unspecified_fixture')
    event['pointer_return64']=hex(result)
    event['allocated_owner_premise']={'address':hex(result),'size_bytes':N,'initial_bytes_defined':False} if result else None
    if result:owner(v,result,N)
    return event

def case(index,parent,pattern,result,zero):
    before=unpack(parent['intervals'][-1]['packed']);v=Parent.restore(before)
    assert before['boundary']['pc']==hex(Parent.NEXT) and before['boundary']['registers31'][0]==hex(N)
    effects=[]
    if zero:
        effect={'address':hex(J+0x100),'bytes_hex':'00'*8,'provenance':'separate_existing_table_NULL_control'}
        v.foreign_fixture(J+0x100,bytes(8),effect['provenance']);effects.append(effect)
        v.cut_stops={SKIP}
    event=pointer_return(v,before,result,pattern);Parent.compact(v)
    row=v.interval(ENTRY,'separate_table_NULL_control' if zero else 'auxiliary_initializer_and_table_read_frontier')
    assert row['boundary']['pc']==hex(SKIP if zero else STOP)
    if not zero:
        assert row['boundary']['kind']=='before_undefined_foreign_owner_read'
        assert row['boundary']['detail']=={'address':'0x650011527c','size_bytes':8}
    return {'parent_case_index':index,'ABI_clobber_pattern':pattern,'pointer_return64':hex(result),
            'table_NULL_control':zero,'effects':effects,'import_return':event,'intervals_packed':[pack(row)],'counts':rc(row)}

def intervals(e):
    for c in e['cases']:
        for p in c['intervals_packed']:yield unpack(p)

def source():
    spans=[('allocation_NULL_partition',ENTRY,0x10054b468),
           ('auxiliary_initializer',0x1007fccd8,0x1007fce10),
           ('existing_table_admission',0x10050e008,0x10050e050),
           ('encoded_table_record_decode',0x100865de0,STOP),
           ('unexecuted_table_swap_loop',STOP,0x100866124)]
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for name,a,b in spans]

def build():
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')))
    cases=[case(j,c,pattern,result,zero) for j,c in enumerate(parent['cases'])
           for pattern in [0,1] for result in [0,B] for zero in [False,True]]
    e={'cases':cases};counts=Counter();used=set()
    for row in intervals(e):
        counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'dependencies':{n:sha(ROOT/n) for n in DEPS},'source_regions':source(),'source_fixups':fixups(used),**e,
            'verified_counts':{'cases':len(cases),'main_cases':8,'table_NULL_controls':8,'intervals':len(cases),**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
