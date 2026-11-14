#!/usr/bin/env python3
"""Complete original mixed-table consumer and caller status continuation.

Four full-machine/controller classes are replayed; every member requires exact
ordered incoming-byte admission and receives its own terminal export.
No new input/API return, native target API/IPC/filesystem/allocation/free,
hardware PAC or IDB mutation. O(parents+visits+effects+source) time/storage.
"""
import json
from collections import Counter,defaultdict
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_state_table_mixing as Parent

P='daemon_table_consumer';ENTRY=Parent.NEXT_CALL;CALLEE=0x1004172f4;RETURN=ENTRY+4
UNKNOWN=0x10057ac04;FIRST=Parent.FIRST;SECOND=Parent.SECOND
S=Parent.S;T=Parent.T;U=Parent.U;J=Parent.J
pack=Parent.pack;unpack=Parent.unpack;restore=Parent.restore;rc=Parent.rc
registers=Parent.registers;terminal=Parent.terminal;source=Parent.source;key=Parent.Parent.key
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_state_table_mixing.py','replay_daemon_state_table_mixing.py','audit_daemon_state_table_mixing.py',
      'daemon_state_table_mixing_checks.json','daemon_state_table_mixing_replay.json','daemon_state_table_mixing_audit.json',
      'recover_daemon_context_lock_use.py','recover_daemon_context_unseal.py','recover_daemon_network_identity.py',
      'recover_daemon_state_file_admission.py','recover_daemon_state_container_construction.py']

def intervals(e):
    for c in e['classes']:
        for x in c['intervals']:yield unpack(x['interval_packed'])

def build():
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')))
    assert sha(ROOT/(Parent.P+'_checks.json'))=='48880e37460e2a7bf8862ebb59b739357791656bcb426a4b2ecc4643a94edbe7'
    parents={x['parent_index']:unpack(x['derived_terminal_state_packed']) for x in parent['coverage']}
    groups=defaultdict(list)
    for i,b in parents.items():groups[key(b)].append(i)
    assert len(parents)==76 and len(groups)==4
    classes=[];coverage=[];counts=Counter();used=set();all_rows=[]
    for members in groups.values():
        representative=members[0];before=parents[representative];v=restore(before);v.cut_stops={RETURN}
        call=v.interval(ENTRY,'original_complete_mixed_table_consumer')
        assert call['boundary']['pc']==hex(RETURN) and call['boundary']['kind']=='before_explicit_source_cut'
        Parent.Parent.Parent.API.compact(v);v.cut_stops=set()
        tail=v.interval(RETURN,'original_status_comparison_to_undefined_caller_field')
        assert tail['boundary']['pc']==hex(UNKNOWN) and tail['boundary']['kind']=='before_unknown_private_read'
        assert tail['boundary']['detail']['address']==hex(int(tail['boundary']['SP'],16)+0x5b0)
        rows=[call,tail];projection=registers(rows);ci=len(classes)
        classes.append({'representative_parent_index':representative,'member_parent_indices':members,'class_key':key(before),
                        'intervals':[{'interval_packed':pack(r)} for r in rows],'register_projection':projection})
        for i in members:coverage.append({'parent_index':i,'class_index':ci,'derived_terminal_state_packed':pack(terminal(parents[i],rows,projection))})
        all_rows.extend(rows)
        print(json.dumps({'representative':representative,'members':len(members),'source_visits':sum(len(r['source_visits']) for r in rows),'boundary':tail['boundary']['pc']}),flush=True)
    for r in all_rows:
        counts.update(rc(r));used.update(int(x['address'],16) for x in r['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'classes':classes,'coverage':coverage,'source_regions':source(all_rows),
            'source_fixups':Parent.Parent.Parent.API.Parent.fixups(used),
            'verified_counts':{'incoming_parents':76,'representative_classes':4,'intervals':len(all_rows),**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
