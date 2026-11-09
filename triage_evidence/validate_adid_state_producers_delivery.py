#!/usr/bin/env python3
"""Fresh source,local proofs,general permutation oracle and codec experiments.

O(B+F+R+V) time/space;finite private source caps. Shared declared emulator/API
models,fresh files and independent integer/byte oracles;no native target/API.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA,SOURCE,FIXUPS
from probe_adid_state_producers import Producers
from probe_adid_startup import unpack_records
from adid_state_codec import state_word,open64,close64,MULTIPLIER,XOR_WORD,SWAP_MULTIPLIER


def read(name):return json.loads((ROOT/name).read_text())


def main():
    assertions=[]
    def check(condition,label):
        assert condition,label
        assertions.append(label)
    s=Adid();p=read('adid_state_producer_profiles.json');c=read('adid_state_producer_contracts.json');rows={r['fixture']['label']:r for r in p['profiles']};events={k:unpack_records(r) for k,r in rows.items()}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh original provider identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_state_producers.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_state_producers.py').read_bytes()),'producer/recoverer pins')
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
        check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'] and ds==w['instructions'],'complete local producer/codec source '+w['start'])
    for proof in c['proofs']+c['prior_byte_proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain local proof '+proof['path'])
    check(c['source_constants']=={'mul_u32':MULTIPLIER,'xor_u32':XOR_WORD,'swap_mul_u32':SWAP_MULTIPLIER},'observed prefix constants and compact-model constants')
    baseline=read('adid_context_gate_profiles.json')['profiles'][0];check(rows['producer_complete_callback']['ordered_original_instruction_sha256']==baseline['ordered_original_instruction_sha256'],'observer preserves complete original callback source')
    total=0;swap_steps=0;aligned=0;unaligned=0;fresh_views=0;byte_count=0;classes=set();state_low_bytes=set();prefix_inputs=set()
    for label,row in rows.items():
        packed=zlib.decompress(base64.b64decode(row['visited_original_instructions_zlib_base64']));h=hashlib.sha256();check(len(packed)==row['visited_original_instruction_count']*8,'visit extent '+label)
        for (pc,) in struct.iter_unpack('<Q',packed):h.update(struct.pack('<Q',pc));h.update(instructions[pc])
        total+=len(packed)//8;check(h.hexdigest()==row['ordered_original_instruction_sha256'],'complete ordered source '+label);check(row['steps']<=row['fixture']['instruction_budget']+1,'finite source cap '+label)
        es=events[label]
        def one(kind):
            selected=[e for e in es if e['kind']==kind];check(len(selected)==1,'one '+kind+' '+label);return selected[0]
        inputs=one('original_state_producer_inputs');state=one('original_state_word');after_swaps=one('original_state_after_swaps');view=one('original_state_view_complete')
        address=int(inputs['address'],16);raw=bytes.fromhex(inputs['input64']);output=bytes.fromhex(view['output64']);key=(((address&0xffffffff)*inputs['mul_u32'])&0xffffffff)^inputs['xor_u32'];constants=(inputs['mul_u32'],inputs['xor_u32'],inputs['swap_mul_u32']);prefix_inputs.add(constants)
        check(constants==(MULTIPLIER,XOR_WORD,SWAP_MULTIPLIER) and key==state['state_u32']==state_word(address),'original scalar producer data flow '+label)
        check(state['address']==after_swaps['address']==view['address']==inputs['address'],'all stages use same source object address '+label)
        words=list(struct.unpack('<8Q',raw));indices=[];source_steps=[e for e in es if e['kind']=='original_state_swap'];check(len(source_steps)==7,'seven original swap iterations '+label)
        for i,e in enumerate(source_steps,1):
            value=((((i+key)&0xffffffff)^key)*inputs['swap_mul_u32'])&0xffffffff;j=value%i;indices.append(j)
            check(e['iteration_u32']==i and e['selected_index_u32']==j and j<i and e['state_u32']==key,'independent general swap-index oracle '+label+' '+str(i))
            words[i],words[j]=words[j],words[i];swap_steps+=1
        shuffled=struct.pack('<8Q',*words);check(shuffled.hex()==after_swaps['bytes64'],'independent complete word-permutation oracle '+label)
        expected=bytes(((155*x)&255)^((((i+key)*(i-key))^key)&255) for i,x in enumerate(shuffled));check(expected==output,'independent complete byte-phase oracle '+label);byte_count+=64
        inverse_bytes=bytes((147*(y^((((i+key)*(i-key))^key)&255)))&255 for i,y in enumerate(output));restored=list(struct.unpack('<8Q',inverse_bytes))
        for i in range(7,0,-1):restored[i],restored[indices[i-1]]=restored[indices[i-1]],restored[i]
        check(struct.pack('<8Q',*restored)==raw,'independent general full-block inverse '+label)
        if address&7==0:
            aligned+=1;check(indices==[0]*7 and key&7==0,'aligned source permutation collapses to rotation '+label)
            check(open64(raw,address)==output and close64(output,address)==raw,'compact complete codec agrees with original source '+label)
        else:
            unaligned+=1;check(any(indices) and list(struct.unpack('<8Q',shuffled))!=list(struct.unpack('<8Q',raw))[-1:]+list(struct.unpack('<8Q',raw))[:-1],'unaligned original source falsifies fixed rotation '+label)
            try:open64(raw,address)
            except ValueError:rejected=True
            else:rejected=False
            check(rejected,'compact codec excludes unsupported unaligned domain '+label)
        f=row['fixture']
        if 'target_view64' in f:
            fixture=one('analyst_owned_state_fixture');fresh_views+=1;classes.add(address&255);state_low_bytes.add(key&255)
            check(fixture['native_valid_context_inferred'] is False and fixture['new_pointer']==inputs['address'] and fixture['prepared_input64']==inputs['input64'] and f['target_view64']==view['output64'],'fresh encoded fixture decodes to independent requested view '+label)
        if f.get('stop_after_state_view'):check(row['stop_reason']=='original_state_view_boundary','bounded original state-view completion '+label)
        else:check(row['stop_reason']=='returned_to_private_fixture' and any(e.get('name')=='_xpc_dictionary_set_data' and e['payload_bytes']=='ffff501f' for e in es),'unmodified complete callback result preserved '+label)
    check(classes==set(range(0,256,8)) and len(state_low_bytes)==32 and all(v&7==0 for v in state_low_bytes),'all aligned low-byte address/state classes checked')
    check(prefix_inputs=={(MULTIPLIER,XOR_WORD,SWAP_MULTIPLIER)},'all retained original prefixes share stated constants only')
    replay_steps=0;replays=0;checkpoint=read('adid_peer_checkpoint.json')
    for label in ['producer_complete_callback','producer_nonroot_ready_record_501','owned_aligned_0x0','owned_aligned_0x68','owned_aligned_0xf8','owned_unaligned_7']:
        q=Producers(s,json.loads(json.dumps(rows[label]['fixture'])),checkpoint);actual=q.run_continuation();replays+=1;replay_steps+=actual['steps']
        check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and actual['stop_reason']==rows[label]['stop_reason'] and unpack_records(actual)==events[label],'fresh complete source/event replay '+label)
    for r in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/r['path'];check(path.stat().st_size==r['size_bytes'] and sha(path.read_bytes())==r['sha256'],'original input preserved '+r['path'])
    counts={'private_cases':len(rows),'aligned_source_cases':aligned,'unaligned_source_counterexamples':unaligned,'fresh_prepared_views':fresh_views,'aligned_address_classes':len(classes),'observed_state_low_byte_classes':len(state_low_bytes),'original_instruction_records':len(instructions),'original_compiler_ranges':len(p['original_functions']),'retained_original_visits':total,'original_swap_steps':swap_steps,'complete_codec_bytes_checked':byte_count,'new_SMT_unsat':len(c['proofs']),'prior_byte_SMT_readbacks':len(c['prior_byte_proofs']),'complete_source_windows':len(c['original_windows']),'independent_replay_runs':replays,'independent_replay_steps':replay_steps,'assertions':len(assertions)}
    out={'scope':__doc__,'verified_counts':counts,'checks':assertions,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_state_producer_checks.json').write_text(json.dumps(out,indent=2)+'\n')
    quality={'scope':'Address-derived state word,aligned rotation,complete local codec,fresh aligned views and unaligned counterexamples;full goal active.','verified_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    texts=['Descriptive findings.','Report V1-V9 state assumptions/dependencies/falsification probes.','Compact semantic recovery and original producer/interface progress;valid context/native/full goal incomplete.','Four new local proofs,two prior byte proofs,general permutation/inverse oracles and exact byte/word extents.','Alignment,source-prefix constants,relocation fixtures,mathematical inverse versus native routine and native-type unknowns separated.','Fresh original bytes/fixups and six source replays;all original inputs preserved.','Impact-labeled real record grammar,key/pointer producers,whole-request/native/provider/rights and deeper RPC contracts.']
    for j,t in enumerate(texts,1):quality['QG'+str(j)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'adid_state_producer_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
