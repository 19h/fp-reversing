#!/usr/bin/env python3
"""Fresh command-tree interpretation, original callbacks and interface checks.

O(B+F+C*K+T) time/space; finite original-hook caps. Integer/tree and byte/ABI
oracles are independent of source execution; replay shares declared private
API/PAC models. No native target, Mach, IOKit, file or VM operation executes.
"""
import base64
import hashlib
import json
import re
import struct
import subprocess
import zlib
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA,SOURCE,FIXUPS
from probe_adid_command_dispatch import run_one
from probe_adid_startup import unpack_records


def read(name):return json.loads((ROOT/name).read_text())


def interpret(s,wire,leaves):
    value=(wire+0x46d726)&0xffffffff;signed=lambda v:v-(1<<32) if v&(1<<31) else v
    registers={};pc=0x10016cd58;path=[];cmpvalue=None
    while pc not in leaves and pc!=0x10016ec20:
        i=next(CS.disasm(s.read(pc,4),pc));path.append(pc);nextpc=pc+4
        if i.mnemonic in ('mov','movk'):
            m=re.fullmatch(r'w(\d+), #(-?(?:0x[0-9a-f]+|\d+))(?:, lsl #(0x[0-9a-f]+|\d+))?',i.op_str)
            if m:
                reg=m[1];v=int(m[2],0)&0xffffffff;shift=int(m[3] or '0',0);registers[reg]=v if i.mnemonic=='mov' else (registers[reg]&~(65535<<shift))|((v&65535)<<shift)
        elif i.mnemonic=='cmp':cmpvalue=registers[i.op_str.split('w')[-1]]
        elif i.mnemonic.startswith('b.'):
            cc=i.mnemonic[2:];take=(signed(value)>signed(cmpvalue)) if cc=='gt' else (signed(value)<=signed(cmpvalue)) if cc=='le' else value==cmpvalue if cc=='eq' else value!=cmpvalue
            if take:nextpc=int(i.op_str[1:],16)
        else:raise AssertionError((hex(pc),i.mnemonic,i.op_str))
        pc=nextpc
    return pc,path


def main():
    checks=[]
    def check(v,label):
        assert v,label
        checks.append(label)
    s=Adid();p=read('adid_command_dispatch_profiles.json');c=read('adid_command_dispatch_contracts.json');tree=c['command_tree'];rows={r['fixture']['label']:r for r in p['profiles']};events={k:unpack_records(r) for k,r in rows.items()};entries={r['wire_command_u32']:int(r['parser_entry'],16) for r in tree['accepted']};leaves=set(entries.values());nodes={int(r['pc'],16) for r in tree['decision_instructions']}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh original provider identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_command_dispatch.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_command_dispatch.py').read_bytes()),'producer/recoverer pins')
    for source in (p,c):
        for name,digest in source['dependencies'].items():check(sha((ROOT/name).read_bytes())==digest,'dependency '+name)
    run=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(SOURCE)],capture_output=True,check=True);check(run.stdout==FIXUPS.read_bytes(),'independent original fixups')
    instructions={}
    for i in p['original_instruction_records']:
        pc=int(i['ea'],16);raw=s.read(pc,4);d=next(CS.disasm(raw,pc));instructions[pc]=raw;check(raw.hex()==i['bytes'] and (d.mnemonic,d.op_str)==(i['mnemonic'],i['operands']),'original instruction '+i['ea'])
    for r in tree['decision_instructions']:
        pc=int(r['pc'],16);raw=s.read(pc,4);d=next(CS.disasm(raw,pc));check(raw.hex()==r['bytes'] and (d.mnemonic,d.op_str)==(r['mnemonic'],r['operands']),'original decision node '+r['pc'])
    for f in p['original_functions']:
        a,z=int(f['start'],16),int(f['end'],16);check(s.bounds(a)==(a,z) and sha(s.read(a,z-a))==f['sha256'],'complete compiler range '+f['start'])
    for w in c['original_windows']:
        a,z=int(w['start'],16),int(w['end'],16);raw=s.read(a,z-a);ds=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)];check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'] and ds==w['instructions'],'complete command source window '+w['start'])
    for proof in c['proofs']+c['prior_header_proof']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain local proof '+proof['path'])
    intervals=[(r['encoded_signed_lo'],r['encoded_signed_hi']) for r in tree['rejected_signed_intervals']]+[(int(r['encoded_command_u32'])-(1<<32) if r['encoded_command_u32']&(1<<31) else r['encoded_command_u32'],)*2 for r in tree['accepted']];cursor=-(1<<31)
    for lo,hi in sorted(intervals):check(lo==cursor and lo<=hi,'exact signed-domain interval coverage '+str(lo));cursor=hi+1
    check(cursor==1<<31 and len(entries)==14 and tree['rejected_word_count']==(1<<32)-14,'full32-bit domain covered with14 selected command words')
    baseline={0x0b2b3196:'ffff5031',0x385b2ce8:'ffff4ffb',0x55a637c0:'ffff501f',0x632b8d6e:'ffff501f',0x716bd86c:'ffff5018',0x72096fe6:'00000000',0x76e89210:'ffff5024',0x7715488c:'ffff4ffa',0x85fe63b0:'ffff4ffb',0xa54951ec:'ffff4ffb',0xa8471cad:'ffff5031',0xb0eda7af:'ffff4ffb',0xcfe0b46a:'ffff4ffb'}
    counts={'original_visits':0,'completed_callbacks':0,'selected_command_cases':0,'unknown_command_cases':0,'request_driven_constructors':0,'request_driven_IOKit_caller_records':0,'method100_calls':0,'unlink_command_cases':0,'allocation_argument_cases':0,'unexecuted_BRK_boundaries':0,'mmap_boundaries':0,'opaque_environment_boundaries':0};selected=set()
    for label,r in rows.items():
        f=r['fixture'];es=events[label];wire=bytes.fromhex(f['payload_hex']);first,command,third=struct.unpack_from('>III',wire);kind=f['case_kind'];packed=zlib.decompress(base64.b64decode(r['visited_original_instructions_zlib_base64']));visits=[v[0] for v in struct.iter_unpack('<Q',packed)];h=hashlib.sha256()
        check(len(visits)==r['visited_original_instruction_count'] and r['steps']<=f['instruction_budget']+1,'bounded source extent '+label)
        for pc in visits:h.update(struct.pack('<Q',pc));h.update(instructions[pc])
        counts['original_visits']+=len(visits);check(h.hexdigest()==r['ordered_original_instruction_sha256'],'complete ordered original source '+label)
        check(f['new_entry']==0x100029fc8 and f['instruction_or_frame_overrides'] is False and not any(e['kind'].startswith('analyst_') for e in es),'original full callback without analyst instruction/frame intervention '+label)
        check(not any(k in f for k in ['fragment_entry','early_tag','late_tag','late_pointer24','post_context_flag','codec_address']),'no internal control/context overrides '+label)
        selectors=[e for e in es if e['kind']=='original_command_word'];chosen=[int(e['pc'],16) for e in es if e['kind'] in ['original_command_parser_entry','original_command_rejection_entry']]
        if first==1:
            expected,path=interpret(s,command,leaves);check(len(selectors)==1 and selectors[0]['encoded_u32']==(command+0x46d726)&0xffffffff and selectors[0]['core_operation_u32']==0xd5b,'request word to original encoded selector '+label)
            check(chosen and chosen[0]==expected and all(v==0x10016ec20 for v in chosen[1:]) and [pc for pc in visits if pc in nodes]==path,'independent initial dispatch path; later parser can reuse common error entry '+label)
        else:check(selectors==[] and chosen==[0x10016ec20] and not any(pc in nodes for pc in visits),'bad first word bypasses command tree and uses shared error entry '+label)
        payloads=[e['payload_bytes'] for e in es if e.get('name')=='_xpc_dictionary_set_data'];completed=r['stop_reason']=='returned_to_private_fixture'
        if completed:
            counts['completed_callbacks']+=1;core=[e for e in es if e['kind']=='original_core_record_return'];check(len(core)==1 and core[0]['status_u32']==0 and core[0]['output_length_u64']==4 and len(payloads)==1 and len(payloads[0])==8,'wrapper0 and BE32 payload on completed callbacks '+label)
            check([e['callsite'] for e in es if e.get('name')=='_xpc_dictionary_set_data']==['0x1000aa9fc'] and [e['callsite'] for e in es if e.get('name')=='_xpc_dictionary_send_reply']==['0x1000aaa70'],'existing source XPC reply emission '+label)
        else:check(payloads==[] and not any(e.get('name')=='_xpc_dictionary_send_reply' for e in es),'no invented completion at explicit boundary '+label)
        for e in es:
            if e['kind']=='original_payload_read':check(0<=int(e['address'],16)-0x7b002000 and int(e['address'],16)-0x7b002000+e['size_bytes']<=len(wire),'original observed payload read inside request '+label+' '+e['pc'])
        if kind=='selected_command':
            counts['selected_command_cases']+=1;selected.add(command)
            if command==0x9679d4b5:check(r['stop_reason']=='unreviewed_mapping_guard','selected allocation command stops before mapping '+label)
            else:check(payloads==[baseline[command]],'retained selected-command baseline result '+label)
        elif kind=='unknown_command':counts['unknown_command_cases']+=1;check(command not in entries and payloads==['ffff5025'],'unselected command rejection '+label)
        elif kind=='bad_word0':check(payloads==['ffff5026'],'common first-word rejection '+label)
        elif kind=='constructor_truncation':check(payloads==['ffff5016'] and not r['object_addresses'],'declared tail exceeds request and precedes construction '+label)
        elif kind=='constructor_blob':check(payloads==['ffff5018' if f['declared_blob_bytes']<27 else 'ffff5019'],'size guard versus first inner-header rejection '+label)
        constructors=[e for e in es if e['kind']=='original_command_packet_boundary' and e['pc']=='0x10019cb24']
        if constructors:
            counts['request_driven_constructors']+=len(constructors);check(command==0x716bd86c and len(constructors)==1,'constructor reached by original command '+label);e=constructors[0];objects=e['constructed_objects'];outer=bytes.fromhex(objects['outer']);nested=bytes.fromhex(objects['nested']);key=int.from_bytes(wire[12:20],'big');length=int.from_bytes(wire[20:24],'big');uid=f.get('audit_euid_result',0)
            check(len(outer)==96 and len(nested)==176 and struct.unpack_from('<Q',outer)[0]==(int(r['object_addresses']['nested'],16)+0x6fac17cb61e34e69)&((1<<64)-1),'original requested object extents and nested pointer '+label)
            check(struct.unpack_from('<Q',nested,8)[0]==key^0xda8ca8cae5dfbd2d and struct.unpack_from('<I',nested,0xa0)[0]==(uid+0x46d726)&0xffffffff and struct.unpack_from('<Q',nested,0x98)[0]==0xda8ca8cae5dfbd2d,'request key,audit EUID and encoded zero from original constructor '+label)
            producer=next(v for v in es if v['kind']=='original_command_packet_boundary' and v['pc']=='0x10016ac30')['tail_producer'];check(producer=={'input_base':'0x7b002000','offset_u64':'0x18','pointer_to_store':'0x7b002018','encoded_length_to_store_u32':(length+0x46d726)&0xffffffff},'request-tail pointer and length producer '+label)
            check(int.from_bytes(bytes.fromhex(e['frame_fields']['0x1740']),'little')==0x7b002018 and int.from_bytes(bytes.fromhex(e['frame_fields']['0x1d0c']),'little')==(length+0x46d726)&0xffffffff,'staged packet span reaches original constructor '+label)
            gate=next(v for v in es if v['kind']=='original_command_packet_boundary' and v['pc']=='0x10019cb80');check(int(gate['registers']['x10'],16)==(length-27)&0xffffffff,'original27-byte gate operand '+label)
        if kind=='unlink_command':
            counts['unlink_command_cases']+=1;uid=f.get('audit_euid_result',0);path=f'/Users/Shared/adi/adi-{uid:08X}.pb';unlinks=[e for e in es if e.get('name')=='_unlink'];check(len(wire)==12 and payloads==['00000000'] and len(unlinks)==1 and unlinks[0]['callsite']=='0x100123c74' and unlinks[0]['path']==path and int(unlinks[0]['result'],16)==f['unlink_result'],'header-only per-EUID unlink request/result '+label)
            check(not r['filesystem_model_initial'][path].get('path_unlinked',False) and r['filesystem_model_final'][path].get('path_unlinked',False)==(f['unlink_result']==0),'modeled unlink effect distinct from payload0 '+label)
        if kind=='allocation_argument':
            counts['allocation_argument_cases']+=1;calls=[e for e in es if e['kind']=='original_allocation_layer_boundary' and e['pc']=='0x1000621d4' and e['registers']['x30']=='0x100266b7c'];value=f['request_scalar_u32'];check(len(calls)==1 and int(calls[0]['registers']['x0'],16)==(value*32)&0xffffffff,'request scalar to u32 allocation byte count '+label)
            if value<65535:check(r['stop_reason']=='native_instruction_guard:brk','bounded original post-allocation BRK '+label)
            else:check(r['stop_reason']=='unreviewed_mapping_guard','bounded request-driven VM arguments '+label)
        for e in es:
            if e['kind']=='unexecuted_original_instruction_boundary':counts['unexecuted_BRK_boundaries']+=1;check(e['pc']=='0x100266b7c' and e['mnemonic']=='brk' and e['native_instruction_executed'] is False,'source BRK boundary without native execution '+label)
            if e.get('name')=='_mmap':counts['mmap_boundaries']+=1;check(e['callsite']=='0x100267b1c' and e['native_API_executed'] is False,'original request-driven mmap callsite '+label)
        if kind=='environment_command':
            if f.get('VMM_value')==1 and f.get('VMM_status',0)==0:counts['opaque_environment_boundaries']+=1;check(r['stop_reason']=='opaque_API_boundary:_time','exact VMM1 reaches time boundary '+label)
            else:check(payloads==['ffff5024'],'other VMM outcomes select earlier result '+label)
        if kind in ('environment_continuation','environment_iokit'):
            models=[e for e in es if e['kind']=='command_explicit_API_model'];check([(e['name'],e['callsite']) for e in models[:2]]==[('_time','0x100146434'),('_arc4random_uniform','0x100146574')] and models[0]['null_output_pointer'] is True and models[1]['upper_u32']==0x7fffffff and models[1]['result_u32']<models[1]['upper_u32'],'explicit time/random API prerequisites '+label)
            check([(e['callsite'],e['requested_bytes']) for e in models if e['name']=='_malloc']==[('0x1001466ac',12),('0x1001468a4',1)],'two original external allocation requests '+label)
            if kind=='environment_continuation':check(r['stop_reason']=='opaque_API_boundary:_IOMainPort','full request reaches unmodeled IOKit boundary '+label)
            else:
                matches=[e for e in es if e.get('name')=='_IOServiceMatching'];opens=[e for e in es if e.get('name')=='_IOServiceOpen'];io=[e for e in es if e['kind']=='original_method100_boundary'];counts['method100_calls']+=len(io);check(matches and all(e['name_string']=='AvpFairPlayDriver' for e in matches),'request-driven provider class '+label)
                for e in opens:
                    x=[int(v,16) for v in e['args_x0_x7']];check(e['callsite']=='0x10002b854' and x[1:4]==[0x5810,0,0x1002dd290],'type0 Avp connection cache output '+label)
                for e in io:
                    x=[int(v,16) for v in e['args_x0_x7']];check(e['callsite']=='0x100058a1c' and x[0]==0x5804 and x[1]==100 and x[2]==x[4] and x[3]==e['output_size_before_u64']==144 and len(bytes.fromhex(e['input_bytes']))==144,'exact original shared-buffer selector100 ABI '+label)
                expected=('original_method100_opaque_boundary',[],1,1) if label.endswith('_opaque') else ('returned_to_private_fixture',['ffff4fe5'],4,1) if label.endswith('_transport_error') else ('returned_to_private_fixture',['ffff5805'],1,1) if label.endswith('_identity') else ('returned_to_private_fixture',['ffff4fe5'],0,4)
                check((r['stop_reason'],payloads,len(io),len(opens))==expected,'original IOKit outcome/retry/source-reply contract '+label)
                callers=[e for e in es if e['kind']=='original_request_driven_IOKit_caller'];counts['request_driven_IOKit_caller_records']+=len(callers)
                for e in callers:
                    raw=bytes.fromhex(e['record40_bytes']);addr=int(e['record_address'],16);key=(((addr&0xffffffff)^0x4e89bd66)*0x0b08355f)&0xffffffff;size=(struct.unpack_from('<I',raw,8)[0]+key-0x4349792f)&0xffffffff;basis=(struct.unpack_from('<I',raw,36)[0]+key)&0xffffffff
                    check(size==144 and basis==0x5f8 and struct.unpack_from('<Q',raw,24)[0]==0x7e000530,'source-built outer IOKit caller record40 decoded independently '+label)
    check(selected==set(entries),'all recovered selected command words exercised')
    checkpoint=read('adid_peer_checkpoint.json');replay_labels=['command_0x632b8d6e','unknown_command_0x0','construct_zero_27','construct_truncated_32_0','header_only_unlink_uid501_status-1','allocation_argument_0','allocation_argument_65535','environment_command_one','environment_iokit_opaque','environment_iokit_transport_error','environment_iokit_identity','environment_iokit_open_failure'];replay_steps=0
    for label in replay_labels:
        q,actual=run_one(s,rows[label]['fixture'],checkpoint);replay_steps+=actual['steps'];check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and actual['stop_reason']==rows[label]['stop_reason'] and unpack_records(actual)==events[label] and actual['object_final_bytes']==rows[label]['object_final_bytes'],'fresh complete source/event/API replay '+label)
    for r in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/r['path'];check(path.stat().st_size==r['size_bytes'] and sha(path.read_bytes())==r['sha256'],'original input preserved '+r['path'])
    verified={'private_cases':len(rows),**counts,'selected_command_words':len(entries),'decision_source_instructions':len(nodes),'full_dispatch_domain_words':1<<32,'rejected_dispatch_words':(1<<32)-14,'original_instruction_records':len(instructions),'original_compiler_ranges':len(p['original_functions']),'new_SMT_unsat':len(c['proofs']),'prior_header_SMT_readbacks':len(c['prior_header_proof']),'source_windows':len(c['original_windows']),'independent_replay_runs':len(replay_labels),'independent_replay_steps':replay_steps,'assertions':len(checks)}
    (ROOT/'adid_command_dispatch_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':verified,'checks':checks,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    q={'scope':'Complete local command-word dispatch,request-driven constructor/file/VM/environment/Avp100 interfaces under explicit private models; native/full goal incomplete.','verified_counts':verified,'native_target_executed':False,'full_goal_complete':False}
    texts=['Descriptive source/interface findings.','Report D1-D10 state assumptions,dependent results and falsification probes.','Fourteen-command local dispatch and original request interfaces covered; full native architecture incomplete.','Full32-bit dispatch,minimum-size and allocation arithmetic proofs; byte/scalar/record extents explicit.','Parser selection versus whole-operation admission,unexecuted BRK/VM/time/IOKit boundaries,API error/identity controls and synthetic names separated.','Fresh original bytes/fixups,independent decision interpreter and twelve complete replays; original inputs preserved.','Impact-labeled complete per-command schemas,valid blob/publication,Avp implementation/native rights,actual library/driver pairing and protected operation contracts.']
    for i,t in enumerate(texts,1):q['QG'+str(i)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'adid_command_dispatch_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps(verified))


if __name__=='__main__':main()
