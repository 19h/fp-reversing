#!/usr/bin/env python3
"""Separate initializer-compatible constructor continuation, eleven root premises.

The inherited frontier remains undefined. Twelve retained initializer profiles
agree on eleven pointers; adding their 88 B is an explicit conditional entry,
not a continuous initializer/caller or native epoch join. Original instructions
run until the next undefined field. No API return, payload input, owner extent,
native operation, hardware PAC or IDB mutation is supplied.
O(parents+visits+effects+source+initializer journals) time/storage.
"""
import json
from collections import Counter,defaultdict
from copy import deepcopy
from daemon_receive_tools import ROOT,SOURCE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
import recover_daemon_table_consumer as Parent

P='daemon_constructor_gate';ENTRY=Parent.UNKNOWN;UNKNOWN=0x1005f149c
GATE=0x1010b5de0;FLAG=0x1010c5798;D=0x1010b5ef0
OFFSETS=[0x5b0,0x578,0x5b8,0x860,0x420,0x418,0x428,0x3e8,0x3e0,0x3d8,0x438]
pack=Parent.pack;unpack=Parent.unpack;restore=Parent.restore;rc=Parent.rc
registers=Parent.registers;terminal=Parent.terminal;source=Parent.source;key=Parent.key
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_table_consumer.py','replay_daemon_table_consumer.py','audit_daemon_table_consumer.py',
      'daemon_table_consumer_checks.json','daemon_table_consumer_replay.json','daemon_table_consumer_audit.json',
      'recover_daemon_return_bank_origins.py','daemon_return_bank_origins_checks.json',
      'recover_daemon_context_lock_use.py','recover_daemon_context_unseal.py','recover_daemon_network_identity.py',
      'recover_daemon_state_file_admission.py','recover_daemon_state_container_construction.py']

def roots():
    e=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'));cases=e['upstream_cases'];out=[]
    assert len(cases)==12 and e['source_sha256']==sha(SOURCE) and not e['initializer_to_caller_control_join_established']
    for off in OFFSETS+[0x260]:
        examples=[]
        for j,c in enumerate(cases):
            f=int(c['frame_base'],16);a=f+off
            ww=[w for w in c['source_writes'] if int(w['address'],16)<a+8 and a<int(w['address'],16)+w['size_bytes']]
            assert len(ww)==1 and ww[0]['address']==hex(a) and ww[0]['size_bytes']==8
            w=ww[0];visit=c['source_visits'][w['source_visit_index']]
            assert visit['pc']==w['pc']
            examples.append({'initializer_profile_index':j,'frame_base':hex(f),'writer':w,'source_word_hex':visit['bytes_hex'],'overlapping_writes':1})
        same=len({(x['writer']['pc'],x['writer']['after_hex']) for x in examples})==1
        assert same==(off!=0x260)
        out.append({'offset_bytes':off,'invariant_across_profiles':same,'value64':hex(int.from_bytes(bytes.fromhex(examples[0]['writer']['after_hex']),'little')) if same else None,
                    'examples':examples,'supplied_to_separate_entry':same})
    return {'fields':out,'supplied_bytes':88,'initializer_profiles':12,
            'initializer_to_current_constructor_join_established':False,'native_epoch_join_established':False}

def premised(parent,root_receipt):
    p=deepcopy(parent);memory=state_bytes(parent);sp=int(parent['boundary']['SP'],16);effects=[]
    assert parent['boundary']['pc']==hex(ENTRY)
    for f in root_receipt['fields']:
        if not f['supplied_to_separate_entry']:continue
        a=sp+f['offset_bytes'];assert all(a+j not in memory for j in range(8))
        effects.append({'address':hex(a),'bytes_hex':int(f['value64'],16).to_bytes(8,'little').hex(),
                        'provenance':'explicit_separate_initializer_compatible_entry_premise'})
    assert len(effects)==11
    p['initial_private_fixtures']+=effects
    p['role']='separate_conditional_entry_with_eleven_source_compatible_roots'
    return p,effects

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')))
    assert sha(ROOT/(Parent.P+'_checks.json'))=='5137ecaa23c9984c362309dced8482323b1aca63357dcac61d3de3090a695f14'
    parents={x['parent_index']:unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    root_receipt=roots();groups=defaultdict(list)
    for i,b in parents.items():groups[key(b)].append(i)
    assert len(parents)==76 and len(groups)==4
    classes=[];coverage=[];counts=Counter();used=set();all_rows=[]
    for members in groups.values():
        representative=members[0];before,effects=premised(parents[representative],root_receipt)
        v=restore(before);v.cut_stops=set();row=v.interval(ENTRY,'separate_initializer_compatible_constructor_continuation')
        assert row['boundary']['pc']==hex(UNKNOWN) and row['boundary']['kind']=='before_unknown_private_read'
        assert row['boundary']['detail']['address']==hex(int(row['boundary']['SP'],16)+0x260)
        projection=registers([row]);ci=len(classes)
        classes.append({'representative_parent_index':representative,'member_parent_indices':members,'class_key':key(before),
                        'entry_premises':effects,'interval_packed':pack(row),'register_projection':projection})
        for i in members:
            admitted,fx=premised(parents[i],root_receipt);out=terminal(admitted,[row],projection)
            out['role']='conditional_terminal_with_eleven_explicit_root_premises'
            for kind in ['private','image']:
                for f in out['initial_'+kind+'_fixtures']:f['provenance']='inherited_definitions_explicit_root_premises_and_original_source_effects'
            coverage.append({'parent_index':i,'class_index':ci,'entry_premises':fx,'derived_terminal_state_packed':pack(out)})
        all_rows.append(row);counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
        print(json.dumps({'representative':representative,'members':len(members),**rc(row),'boundary':row['boundary']['pc']}),flush=True)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'root_provenance':root_receipt,'classes':classes,'coverage':coverage,'source_regions':source(all_rows),
            'source_fixups':Parent.Parent.Parent.Parent.API.Parent.fixups(used),
            'verified_counts':{'incoming_parents':76,'representative_classes':4,'intervals':4,'new_root_premise_bytes_per_parent':88,**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,
            'continuous_initializer_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
