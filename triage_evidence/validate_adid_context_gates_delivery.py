#!/usr/bin/env python3
"""Fresh context-gate/byte-transform/source-mutation-ledger validation.

O(B+F+R+V) time/space;finite private source-hook caps. Fresh source,local SMT,
Python byte oracle and declared-model replays;no native target/host operation.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA,SOURCE,FIXUPS
from probe_adid_context_gates import Gates,BLOCK
from probe_adid_startup import unpack_records


def read(name):return json.loads((ROOT/name).read_text())


def main():
    assertions=[]
    def check(condition,label):
        assert condition,label
        assertions.append(label)
    s=Adid();p=read('adid_context_gate_profiles.json');c=read('adid_context_gate_contracts.json');rows={r['fixture']['label']:r for r in p['profiles']};events={k:unpack_records(r) for k,r in rows.items()}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh original provider identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_context_gates.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_context_gates.py').read_bytes()),'producer/recoverer pins')
    for source in (p,c):
        for name,digest in source['dependencies'].items():check(sha((ROOT/name).read_bytes())==digest,'dependency '+name)
    run=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(SOURCE)],capture_output=True,check=True);check(run.stdout==FIXUPS.read_bytes(),'independent original pointer display')
    instructions={}
    for i in p['original_instruction_records']:
        pc=int(i['ea'],16);raw=s.read(pc,4);d=next(CS.disasm(raw,pc));instructions[pc]=raw
        check(raw.hex()==i['bytes'] and d.mnemonic==i['mnemonic'] and d.op_str==i['operands'],'fresh original instruction '+i['ea'])
    for f in p['original_functions']:
        a,z=int(f['start'],16),int(f['end'],16);check(s.bounds(a)==(a,z) and sha(s.read(a,z-a))==f['sha256'],'complete compiler range '+f['start'])
    for w in c['original_windows']:
        a,z=int(w['start'],16),int(w['end'],16);raw=s.read(a,z-a);ds=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]
        check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'] and ds==w['instructions'],'source gate/vector window '+w['start'])
    for branch in c['guard_branches']:
        ptr=branch['pointer'];check(int(ptr['address'],16)==int(c['branch_table_base'],16)+8*branch['index'] and s.decoded[int(ptr['address'],16)]==ptr,'original guard pointer '+hex(branch['index']))
    for lit in c['vector_literals']:check(s.read(int(lit['address'],16),16).hex()==lit['bytes16'],'original vector constant '+lit['address'])
    check(bytes.fromhex(c['vector_literals'][-1]['bytes16'])==bytes(range(0,64,4)),'literal low-byte gather indices')
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain local proof '+proof['path'])
    old=next(r for r in read('adid_context_profiles.json')['profiles'] if r['fixture']['label']=='context_error_producer');check(old['ordered_original_instruction_sha256']==rows['gate_baseline']['ordered_original_instruction_sha256'],'baseline preserves original complete callback source path')
    total=0;source_effects=0;api_calls=0;api_effects=0;chunks=0;bytes_checked=0;completed=0;private_stops=0
    for label,row in rows.items():
        f=row['fixture'];packed=zlib.decompress(base64.b64decode(row['visited_original_instructions_zlib_base64']));h=hashlib.sha256();check(len(packed)==row['visited_original_instruction_count']*8,'visit extent '+label)
        for (pc,) in struct.iter_unpack('<Q',packed):h.update(struct.pack('<Q',pc));h.update(instructions[pc])
        total+=len(packed)//8;check(h.hexdigest()==row['ordered_original_instruction_sha256'],'complete ordered original source '+label);check(row['steps']<=f['instruction_budget']+1,'finite hook cap '+label)
        ledger=bytes.fromhex(row['context_block_initial_bytes64']);api_calls+=row['context_memory_API_calls_checked'];seen_chunks=[];branch_targets={};tag_load=None
        for e in events[label]:
            if 'before_bytes64' in e and 'after_bytes64' in e:
                before=bytes.fromhex(e['before_bytes64']);after=bytes.fromhex(e['after_bytes64']);check(before==ledger,'continuous complete block mutation provenance '+label+' '+e['kind'])
                if e['kind']=='original_context_memory_write_effect':
                    source_effects+=1;expected=bytearray(before)
                    for write in e['writes']:
                        check(write['size_bytes']<=8,'full observed write value width '+label);address=int(write['address'],16);raw=int(write['hook_value_low_u64'],16).to_bytes(write['size_bytes'],'little')
                        for j,b in enumerate(raw):
                            if BLOCK<=address+j<BLOCK+64:expected[address+j-BLOCK]=b
                    check(bytes(expected)==after,'independent source-store effect on entire block '+label+' '+e['pc'])
                elif e['kind'].startswith('analyst_'):check(e['native_state_inferred'] is False,'private mutation remains explicit '+label)
                elif e['kind']=='modeled_API_context_memory_effect':api_effects+=1;check(e['native_API_executed'] is False,'modeled API mutation scope '+label)
                else:check(False,'unclassified block mutation '+label)
                ledger=after
            if e['kind']=='original_context_table_vector':
                chunks+=1;seen_chunks.append(e['offset_bytes']);key=e['key_u32'];offset=e['offset_bytes'];input_bytes=bytes.fromhex(e['input16']);output=bytes.fromhex(e['output16']);table=bytes.fromhex(e['table64']);indices=bytes.fromhex(e['indices16'])
                check(offset in (0,16,32,48) and int(e['base'],16)==BLOCK and int(e['address'],16)==int(e['store_address'],16)==BLOCK+offset,'source transform span and address '+label)
                check(indices==bytes(range(0,64,4)) and bytes(table[j] if j<len(table) else 0 for j in indices)==output,'independent table-gather oracle '+label)
                for j,raw in enumerate(e['position_vectors_q0_q3']):check(list(struct.unpack('<4I',bytes.fromhex(raw)))==list(range(offset+12-4*j,offset+16-4*j)),'original vector position lanes '+label+' '+str(j))
                expected=bytes(((155*x)&255)^(((((offset+i)+key)*((offset+i)-key))^key)&255) for i,x in enumerate(input_bytes))
                check(expected==output,'compact original state-transform oracle '+label+' '+str(offset))
                inverse=bytes((147*(y^(((((offset+i)+key)*((offset+i)-key))^key)&255)))&255 for i,y in enumerate(output));check(inverse==input_bytes,'independent byte inverse '+label+' '+str(offset));bytes_checked+=len(input_bytes)
            if e['kind']=='original_context_gate_load':
                check(e['base']==hex(BLOCK) and e['state_w20']==0xd5b and bytes.fromhex(e['bytes64'])==ledger,'source gate observes current logical block '+label)
                if e['pc']=='0x10019bdcc':tag_load=int.from_bytes(ledger[:4],'little')
            if e['kind']=='original_context_gate_branch':branch_targets[e['pc']]=e['target']
        check(ledger.hex()==row['context_block_final_bytes64'],'complete block ledger reaches final memory '+label);check(seen_chunks==[0,16,32,48],'complete four-chunk transform observation '+label)
        pointer=f.get('late_pointer24',0x6fac17cb61e34e69);expected='0x10019e6a4' if pointer==0x6fac17cb61e34e69 else '0x10019e4fc';check(branch_targets['0x10019e4f8']==expected,'pointer24 guard branch '+label)
        if pointer!=0x6fac17cb61e34e69:
            expected_address=(pointer+0x9053e8349e1cb19f)&((1<<64)-1);check(events[label][-1]['pc']=='0x10019e604' and int(events[label][-1]['address'],16)==expected_address and events[label][-1]['native_fault_inferred'] is False,'inconsistent pointer24 private read boundary '+label)
        else:
            expected_tag=f.get('late_tag',0x16e4e4d3);check(tag_load==expected_tag,'early patch is overwritten before tag load '+label)
            expected_target='0x10019c098' if expected_tag==0x16e4e4d3 else '0x10019be18';check(branch_targets['0x10019be14']==expected_target,'tag error/continuation partition '+label)
            if expected_tag!=0x16e4e4d3:check(events[label][-1]['pc']=='0x10019c1c4' and events[label][-1]['address']=='0x18' and events[label][-1]['native_fault_inferred'] is False,'inconsistent tag preserves null-related private boundary '+label)
        reply=[e for e in events[label] if e.get('name')=='_xpc_dictionary_set_data']
        if row['stop_reason']=='returned_to_private_fixture':completed+=1;check(len(reply)==1 and reply[0]['payload_bytes']=='ffff501f','completed original payload error '+label)
        else:private_stops+=1;check(row['stop_reason']=='unresolved_private_memory_boundary' and not reply,'private boundary emits no observed reply '+label)
        if 'early_tag' in f:check(row['ordered_original_instruction_sha256']==rows['gate_baseline']['ordered_original_instruction_sha256'],'early tag edits preserve complete source path '+label)
    check(api_effects==0,'no net modeled-API block effects at all measured boundaries')
    replay_steps=0;replays=0;checkpoint=read('adid_peer_checkpoint.json')
    for label in ['gate_baseline','early_tag_0x0','late_tag_0x0','late_tag_0x16e4e4d3','pointer24_0x6fac17cb61e34e68']:
        q=Gates(s,json.loads(json.dumps(rows[label]['fixture'])),checkpoint);actual=q.run_continuation();replay_steps+=actual['steps'];replays+=1
        check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and actual['stop_reason']==rows[label]['stop_reason'] and unpack_records(actual)==events[label] and bytes(q.u.mem_read(BLOCK,64)).hex()==rows[label]['context_block_final_bytes64'] and q.observed_api_calls==rows[label]['context_memory_API_calls_checked'],'fresh complete source/event/block replay '+label)
    for r in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/r['path'];check(path.stat().st_size==r['size_bytes'] and sha(path.read_bytes())==r['sha256'],'original input preserved '+r['path'])
    counts={'private_cases':len(rows),'completed_payload_errors':completed,'private_inconsistent_state_stops':private_stops,'original_instruction_records':len(instructions),'original_compiler_ranges':len(p['original_functions']),'retained_original_visits':total,'complete_block_source_write_effects':source_effects,'modeled_API_boundaries_observed':api_calls,'modeled_API_net_block_changes':api_effects,'vector_chunks':chunks,'compact_transform_bytes_checked':bytes_checked,'SMT_unsat':len(c['proofs']),'source_windows':len(c['original_windows']),'independent_replay_runs':replays,'independent_replay_steps':replay_steps,'assertions':len(assertions)}
    out={'scope':__doc__,'verified_counts':counts,'checks':assertions,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_context_gate_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    quality={'scope':'Local reversible state transform,mutation epochs,source guard predicates and explicit inconsistent-context probes;full goal active.','verified_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    descriptions=['Descriptive findings.','Report G1-G9 give dependencies and falsification boundaries.','Concrete state/data/control/ABI and full-callback evidence progress;valid native contexts and full goal unproved.','Four local proofs,complete64-byte mutation ledger,per-byte inverse and original operand widths.','Early versus late edits,physical versus observed logical state,tag/pointer guards,private versus native boundaries and zero API net effects separated.','Fresh source/fixups,original vector constants,independent Python oracle and five source replays.','Impact-labeled valid constructors,context producers,remaining gates,real provider replies,rights and deeper RPC interfaces.']
    for j,d in enumerate(descriptions,1):quality['QG'+str(j)]={'status':'pass_for_stated_increment','evidence':d}
    (ROOT/'adid_context_gate_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
