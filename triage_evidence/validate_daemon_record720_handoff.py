#!/usr/bin/env python3
"""Rebuild source proofs/inputs, audit typed cutpoints and independently replay
all saved cases. O(source+cases*(visits+effects)+solver resources) time;
O(profiles+largest independent replay) memory. Finite and universal scopes differ.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE
from capture_daemon_record720 import sha
from capture_daemon_record720_handoff import capture,source_inputs
from prove_daemon_record720_handoff import obligations
from replay_daemon_descriptor_producers import unpack
from recover_daemon_descriptor_producers import verify_used_fixups
from probe_daemon_record720_handoff import cases
from replay_daemon_record720_handoff import replay

def audit(c,t):
    F=int(c['SP'],16);R=F+0xde90;P=int(c['allocation_owner_address'],16);U=int(c['logical_U64'],16);D=int(c['logical_D32'],16);V=D^0x8b3dc651;K=(((R&0xffffffff)^0x7cf28be0)*0x83918153)&0xffffffff;events=t['events'];out=Counter()
    def event(pc,kind):
        rows=[e for e in events if e['pc']==hex(pc)and e['kind']==kind];assert len(rows)==1;return rows[0]
    for pc,off,n,value in [(0x100b0b8a0,24,4,(V+K)&0xffffffff),(0x100b0b8ac,16,8,P),(0x100b0b8b0,8,8,U),(0x100b0b8b4,0,4,0x7a3a^K)]:
        e=event(pc,'write');assert int(e['address'],16)==R+off and e['size_bytes']==n and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==value;out['private_record_fields_checked']+=1
    es=t['edges'];assert any(e['pc']=='0x100b0b960'and e['target']=='0x100536e98'and e['slot']=='0x1010a0688'and e['modifier']=='0x566a'for e in es)
    assert any(e['pc']=='0x100537100'and e['target']=='0x100523894'and e['slot']=='0x1010a0238'and e['modifier']=='0x8489'for e in es)
    assert not any(e['kind']=='read'and P<=int(e['address'],16)<P+720 for e in events);assert sum(t['allocation_defined_mask720'])==161
    cursor=int.from_bytes(bytes.fromhex(event(0x100b0b908,'write')['after_hex']),'little');lcg=int.from_bytes(bytes.fromhex(event(0x100537028,'write')['after_hex']),'little');assert lcg==(cursor*0x2e9d+1)&((1<<64)-1)
    temp=event(0x10053704c,'write');assert int.from_bytes(bytes.fromhex(temp['after_hex']),'little')==(cursor-176)&((1<<64)-1);out['LCG_and_cursor_reservations_checked']+=1
    if not c['imported_guard_supplied']:
        assert t['boundary']['pc']=='0x1005238c0'and t['boundary']['kind']=='before_unknown_external_read';assert not any(e['pc']=='0x100523a24'for e in events);out['imported_data_frontiers_preserved']+=1
    else:
        assert any(e['pc']=='0x100523d68'and e['target']=='0x10062a624'and e['slot']=='0x1010770c0'and e['modifier']=='0xeb00'for e in es);out['control7A3A_handler_entries_checked']+=1
        if U==0 or D==0:
            assert t['boundary']['pc']=='0x100435bc4';status=event(0x10061aabc,'write');value=int.from_bytes(bytes.fromhex(status['after_hex']),'little');assert value==(0x74c29d88 if U==0 else 0x74c29d8f)
            assert int.from_bytes(bytes.fromhex(event(0x100537110,'write')['after_hex']),'little')==0;out['completed_adapter_returns_checked']+=1
            pointer=event(0x100be0be8,'write');assert int(pointer['address'],16)==R+8 and int.from_bytes(bytes.fromhex(pointer['after_hex']),'little')==P;out['cleanup_record_epoch_changes_checked']+=1
        else:assert t['boundary']['pc']=='0x10044dd48';out['nonzero_adapter_frontiers_preserved']+=1
    return out

def main():
    source=json.loads((ROOT/'daemon_record720_handoff_source.json').read_text());assert source==capture();p=json.loads((ROOT/'daemon_record720_handoff_proofs.json').read_text());qs,counts=obligations(source);assert counts==p['source_lift_counts'];proof_count=0
    for (name,formula),r in zip(qs,p['proofs']):
        assert name==r['name'];s=z3.Solver();s.set(timeout=30000);s.add(formula);assert str(s.check())=='unsat'
        for fk,hk in [('original_file','original_sha256'),('file','sha256')]:
            path=ROOT/r[fk];assert sha(path)==r[hk];s=z3.Solver();s.set(timeout=30000);s.from_file(str(path));assert str(s.check())=='unsat'
        proof_count+=1
    assert proof_count==len(qs)==len(p['proofs'])==17
    prof=json.loads((ROOT/'daemon_record720_handoff_profiles.json').read_text());assert prof['generator_sha256']==sha(ROOT/'probe_daemon_record720_handoff.py')
    for n,h in prof['dependencies'].items():assert sha(ROOT/n)==h
    totals=Counter();semantic=Counter();fix=set();pool={};frontiers=Counter()
    for row in prof['input_producers']:
        F=int(row['SP'],16);r=source_inputs(F,bytes.fromhex(row['header12_hex']));assert r=={k:v for k,v in row.items()if k!='SP'};semantic['fresh_input_producers_checked']+=1;semantic['input_producer_source_visits_checked']+=r['source_visits']
    expected=list(cases());assert len(expected)==len(prof['cases'])==384
    for j,(row,(c,cfg))in enumerate(zip(prof['cases'],expected)):
        assert row['context']==c and row['configuration']==cfg;t=unpack(row);assert len(t['steps'])==row['source_visits'];semantic.update(audit(c,t));totals.update(replay(c,cfg,t));frontiers[t['boundary']['pc']]+=1;fix.update(int(x,16)for x in t['used_fixups']);pool.update({a:r['bytes_hex']for a,r in t['source_pool'].items()})
        if (j+1)%32==0:print(json.dumps({'fresh_cases_checked':j+1,'independent_A64':totals['A64_instructions_checked']}),flush=True)
    assert frontiers=={'0x1005238c0':192,'0x100435bc4':96,'0x10044dd48':96};original=verify_used_fixups(fix)
    for pc,h in pool.items():assert IMAGE.read(int(pc,16),4).hex()==h
    verified={'source_proofs_rebuilt':proof_count,'SMT_files_checked':proof_count*2,'source_lift_visits':sum(counts.values()),'main_source_visits':sum(r['source_visits']for r in prof['cases']),'distinct_original_opcodes_checked':len(pool),'original_fixups_checked':len(original['records']),'IDB_ranges':len(source['live_IDB_matches']),'IDB_bytes':sum(r['size_bytes']for r in source['live_IDB_matches']),'exhaustive_byte_banks':len(source['exhaustive_bank_rules']),**dict(semantic)}
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_handoff_source.json','daemon_record720_handoff_proofs.json','daemon_record720_handoff_profiles.json','replay_daemon_record720_handoff.py','daemon_record720_handoff_replay.py','capture_daemon_record720_handoff.py','prove_daemon_record720_handoff.py','probe_daemon_record720_handoff.py']},'verified_counts':verified,'independent_A64_totals':dict(totals),'frontier_counts':dict(frontiers),'original_fixups':original,'source_pool':pool,'native_target_executed':False,'idb_mutated':False,'registry_publication_established':False,'new_port_emission_established':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_record720_handoff_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':verified,'independent_A64_totals':dict(totals),'frontiers':dict(frontiers)}),flush=True)
if __name__=='__main__':main()
