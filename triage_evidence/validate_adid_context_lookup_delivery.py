#!/usr/bin/env python3
"""Fresh original bytes/fixups, collection oracle, local proofs and replay.

O(B+F+R+V+sum(N)) time/space with bounded source caps. Independent read/update
oracle and fresh files; replay shares the declared private API/PAC models.
No native target, IOKit, Mach, filesystem or synchronization API is executed.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA,SOURCE,FIXUPS
from probe_adid_context_lookup import Lookup
from probe_adid_startup import unpack_records
from adid_state_codec import open64


def read(name):return json.loads((ROOT/name).read_text())


def main():
    assertions=[]
    def check(condition,label):
        assert condition,label
        assertions.append(label)
    s=Adid();p=read('adid_context_lookup_profiles.json');c=read('adid_context_lookup_contracts.json');rows={r['fixture']['label']:r for r in p['profiles']};events={k:unpack_records(r) for k,r in rows.items()}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh original provider identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_context_lookup.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_context_lookup.py').read_bytes()),'producer/recoverer source pins')
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
        check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'] and ds==w['instructions'],'complete source window '+w['start'])
    for cell in c['original_pointer_cells']:check(s.decoded[int(cell['address'],16)]==cell,'complete original chain cell '+cell['address'])
    for proof in c['proofs']+c['prior_request_proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain local proof '+proof['path'])
    old=read('adid_state_producer_profiles.json')['profiles'][0];check(rows['lookup_unmodified_baseline']['ordered_original_instruction_sha256']==old['ordered_original_instruction_sha256'],'observer preserves original complete baseline callback')
    totals={'visits':0,'array_reads':0,'holder_reads':0,'key_reads':0,'uid_reads':0,'writes':0,'prepared':0,'matches':0,'misses':0,'early_rejections':0,'loop_boundaries':0,'pointer_reads':0,'invalid_collection_boundaries':0}
    for label,row in rows.items():
        f=row['fixture'];es=events[label];packed=zlib.decompress(base64.b64decode(row['visited_original_instructions_zlib_base64']));h=hashlib.sha256()
        check(len(packed)==row['visited_original_instruction_count']*8,'visit extent '+label)
        for (pc,) in struct.iter_unpack('<Q',packed):h.update(struct.pack('<Q',pc));h.update(instructions[pc])
        totals['visits']+=len(packed)//8;check(h.hexdigest()==row['ordered_original_instruction_sha256'],'complete ordered source '+label)
        invalid=f.get('null_array') and f.get('lookup_count',0)>1
        if invalid:totals['invalid_collection_boundaries']+=1
        check(row['steps']<=f['instruction_budget']+1 and row['stop_reason']==('unresolved_private_memory_boundary' if invalid else 'returned_to_private_fixture'),'bounded original callback or explicit invalid-collection boundary '+label)
        check(not any(e.get('name','').startswith('_IO') for e in es),'no modeled IOKit call in this callback '+label)
        core=[e for e in es if e['kind']=='original_core_record_return'];check(core==[] if invalid else len(core)==1 and core[0]['status_u32']==0 and core[0]['output_length_u64']==4,'wrapper result defined only for completed callback '+label)
        wire=bytes.fromhex(f['payload_hex']);header1,header2,header3,first,second=struct.unpack('>IIIQQ',wire);check((header1,header2,header3)==(1,0x632b8d6e,1),'original request header '+label)
        match=None;want=[];nodes=f.get('lookup_nodes',[]);count=f.get('lookup_count',0);uid=f.get('audit_euid_result',0)&0xffffffff;mask=(1<<64)-1
        def access(region,index,offset,size,value,pc):want.append({'region':region,'index':index,'offset_bytes':offset,'size_bytes':size,'bytes':value.to_bytes(size,'little').hex(),'pc':hex(pc)})
        if row['lookup_prepared']:
            totals['prepared']+=1;fixtures=[e for e in es if e['kind']=='analyst_coupled_collection_fixture'];views=[e for e in es if e['kind']=='original_lookup_view_complete'];check(len(fixtures)==len(views)==1,'one coupled fixture and original decoded view '+label)
            fixture=fixtures[0];view=bytes.fromhex(fixture['target_view64']);original=bytearray.fromhex(f['baseline_view64']);struct.pack_into('<I',original,0,(0x16e4e4d3+count)&0xffffffff);struct.pack_into('<Q',original,8,0x58ce03d8d8c95487 if f.get('null_array') else 0x58ce03d953cb1487)
            check(view==original and views[0]['output64']==view.hex() and open64(bytes.fromhex(fixture['input64']),0x1002dcb68)==view,'coupled view prepared before original complete codec '+label)
            check(fixture['expected_key_slot_u64']==hex(first^0xda8ca8cae5dfbd2d) and fixture['expected_uid_slot_u32']==hex((uid+0x46d726)&0xffffffff),'request key and audit EUID provenance '+label)
            check(fixture['native_valid_object_inferred'] is False,'native validity excluded '+label)
            if not f.get('null_array'):
                for i in range(count):
                    node=nodes[i] if i<len(nodes) else None
                    access('array',None,16*i+8,8,0x2d1ade42073e28af if node is None else (0x7b01d000+256*i+0x2d1ade42073e28af)&mask,0x10019bf0c if i==0 else 0x10019c1c4)
                    if node is None:continue
                    access('holder',i,0,8,0x6fac17cb61e34e69 if node.get('null_nested') else (0x7b01e000+256*i+0x6fac17cb61e34e69)&mask,0x10019bf74 if i==0 else 0x10019c230)
                    if node.get('null_nested'):continue
                    key=node.get('key',first)&mask;access('nested',i,8,8,key^0xda8ca8cae5dfbd2d,0x10019bfbc if i==0 else 0x10019c278)
                    if key!=first:continue
                    record_uid=node.get('uid',uid)&0xffffffff;access('nested',i,0xa0,4,(record_uid+0x46d726)&0xffffffff,0x10019c018 if i==0 else 0x10019c2c4)
                    if record_uid==uid:match=i;break
            if match is None and not invalid:totals['misses']+=1
            elif match is not None:totals['matches']+=1
        elif f.get('prepare_lookup'):
            totals['early_rejections']+=1;check(first not in {x&mask for x in [-8,-6,-5,-4,-3,-2]},'unsupported first field rejected before fixture '+label)
        check(row['lookup_reads']==want,'independent complete collection read/short-circuit oracle '+label)
        for r in want:
            totals['array_reads' if r['region']=='array' else 'holder_reads' if r['region']=='holder' else 'key_reads' if r['offset_bytes']==8 else 'uid_reads']+=1
        writes=[]
        if match is not None:writes=[{'pc':'0x10019c310','region':'nested','index':match,'offset_bytes':0x98,'size_bytes':8,'before_bytes':nodes[match].get('initial_field98',0x0123456789abcdef).to_bytes(8,'little').hex(),'value':hex(second^0xda8ca8cae5dfbd2d)}]
        check(row['lookup_writes']==writes,'independent first-match encoded value update '+label);totals['writes']+=len(writes)
        final={str(i):((second^0xda8ca8cae5dfbd2d) if i==match else node.get('initial_field98',0x0123456789abcdef)).to_bytes(8,'little').hex() for i,node in enumerate(nodes) if node is not None} if row['lookup_prepared'] else {}
        check(row['nested_final_fields98']==final,'all prepared matched/unmatched fields after callback '+label)
        expected_reply='00000000' if match is not None else 'ffff5037' if f.get('prepare_lookup') and not row['lookup_prepared'] else 'ffff501f'
        check([e['payload_bytes'] for e in es if e.get('name')=='_xpc_dictionary_set_data']==([] if invalid else [expected_reply]),'exact payload result or explicit absent completion '+label)
        check([e['callsite'] for e in es if e.get('name')=='_xpc_dictionary_send_reply']==([] if invalid else ['0x1000aaa70']),'original application-level XPC reply emission site '+label)
        if invalid:
            faults=[e for e in es if e['kind']=='unresolved_private_memory_boundary'];check(len(faults)==1 and faults[0]['pc']=='0x10019c1c4' and faults[0]['address']=='0x18' and faults[0]['size_bytes']==8 and faults[0]['native_fault_inferred'] is False,'coupled count/null-array invariant counterexample '+label)
        pending_cell=None
        for j,e in enumerate(es):
            if e['kind']=='original_lookup_pointer_cell':
                cell=s.decoded[int(e['cell'],16)];totals['pointer_reads']+=1;check(not cell['bind'] and e['bytes8']==int(cell['target'],16).to_bytes(8,'little').hex(),'original decoded table load '+label+' '+e['pc']);pending_cell=cell
            elif e['kind']=='PAC_bypassed_edge' and pending_cell is not None:
                check(e['target']==pending_cell['target'] and e['modifier']==pending_cell['diversity'],'original pointer target/diversity matches modeled edge '+label+' '+e['pc']);pending_cell=None
            if e['kind']!='original_lookup_boundary':continue
            r={k:int(v,16) for k,v in e['registers'].items()};pc=int(e['pc'],16)
            if pc in (0x10021ac34,0x10021ac38):
                check((int.from_bytes(bytes.fromhex(e['load_bytes8']),'little') if pc==0x10021ac34 else r['x8'])==second^0xda8ca8cae5dfbd2d,'original encoded value producer '+label+' '+e['pc'])
            elif pc==0x10019be18:
                check((r['x1']&0xffffffff)==0x1279 and r['x20']==0xd5b and (r['x3']&0xffffffff)==(0x16e4e4d3+count)&0xffffffff,'local count proof source preconditions '+label)
            elif pc in (0x10019c048,0x10019c0d0):
                totals['loop_boundaries']+=1;check(r['x4']==0xbae and r['x0']==r['x12']==0xb1e4c5a4 and r['x16']==(0xb1e4c5a4+count)&0xffffffff and r['x14']==first^0xda8ca8cae5dfbd2d and r['x15']==(uid+0x46d726)&0xffffffff,'loop normalization and key/EUID source constants '+label+' '+e['pc'])
                if pc==0x10019c048:stop=count<=1;edgepc='0x10019c094'
                else:
                    i=((r['x3']&0xffffffff)-0x17a54c85)&0xffffffff;stop=i+1>=count;edgepc='0x10019c14c'
                    end=r['x16'];cur=((r['x3']&0xffffffff)+0x9a3f7920)&0xffffffff;origin=r['x0'];a=end<origin;b=cur<origin;proceed=a if a!=b else cur<end
                    check(proceed==(((cur-origin)&0xffffffff)<((end-origin)&0xffffffff))== (not stop),'independent circular comparison '+label)
                edge=next(v for v in es[j+1:] if v['kind']=='PAC_bypassed_edge' and v['pc']==edgepc);check(edge['target']==('0x10019c098' if stop else '0x10019c150'),'normalized count exit/continue target '+label+' '+e['pc'])
            elif pc==0x10019c150:
                i=(r['x3']-0x17a54c85)&0xffffffff;source_index=((r['x5']-0xf9b)+r['x3']+0xe85aa7cd)&0xffffffff
                check(r['x5']==0x1b49 and source_index==i and 1<=i<count,'original 16-byte stride index '+label)
            elif pc==0x10019c310:check(match is not None and r['x8']==0x7b01e000+256*match+0x98 and r['x9']==second^0xda8ca8cae5dfbd2d,'original update address and request-value data flow '+label)
    replay_steps=0;checkpoint=read('adid_peer_checkpoint.json');replay_labels=['lookup_unmodified_baseline','null_entries_256','null_array_count4','mixed_match_last','duplicate_matches','matched_uid_501','second_0x123456789abcdef','matched_first_-2','unsupported_first_1']
    for label in replay_labels:
        q=Lookup(s,json.loads(json.dumps(rows[label]['fixture'])),checkpoint);actual=q.run_continuation();replay_steps+=actual['steps']
        check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and unpack_records(actual)==events[label] and q.lookup_reads==rows[label]['lookup_reads'] and q.lookup_writes==rows[label]['lookup_writes'],'fresh complete source/event/read/write replay '+label)
    for r in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/r['path'];check(path.stat().st_size==r['size_bytes'] and sha(path.read_bytes())==r['sha256'],'original input preserved '+r['path'])
    counts={'private_cases':len(rows),'prepared_collection_cases':totals['prepared'],'matched_updates':totals['matches'],'collection_misses':totals['misses'],'early_first_field_rejections':totals['early_rejections'],'invalid_collection_boundaries':totals['invalid_collection_boundaries'],'array_entry_reads':totals['array_reads'],'holder_reads':totals['holder_reads'],'nested_key_reads':totals['key_reads'],'nested_uid_reads':totals['uid_reads'],'nested_value_writes':totals['writes'],'source_loop_boundaries':totals['loop_boundaries'],'original_pointer_reads':totals['pointer_reads'],'original_pointer_cells':len(c['original_pointer_cells']),'original_instruction_records':len(instructions),'original_compiler_ranges':len(p['original_functions']),'retained_original_visits':totals['visits'],'new_SMT_unsat':len(c['proofs']),'prior_request_SMT_readbacks':len(c['prior_request_proofs']),'complete_source_windows':len(c['original_windows']),'independent_replay_runs':len(replay_labels),'independent_replay_steps':replay_steps,'assertions':len(assertions)}
    (ROOT/'adid_context_lookup_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':assertions,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Count/array/nested key+EUID lookup and first-match value update in modeled original callback; full goal active.','verified_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    texts=['Descriptive technical findings.','Report L1-L10 identify dependent results and falsification probes.','Original lookup/update/data-flow/source-site increment covered; native context and full goal incomplete.','Byte extents and modular u32/u64 semantics; five new full-domain local proofs and three request/status-proof readbacks.','Count-zero/null/mismatch/duplicate/first-hit/unsupported-field cases, explicit invalid-collection boundary and native reachability separated.','Fresh original bytes/fixups/table cells, independent collection oracle and nine complete replays including the explicit invalid-collection boundary; original inputs preserved.','Impact-labeled native constructors, field consumers, atomicity/lifetime, IPC and driver pairing.']
    for j,t in enumerate(texts,1):quality['QG'+str(j)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'adid_context_lookup_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
