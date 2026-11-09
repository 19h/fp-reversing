#!/usr/bin/env python3
"""Fresh source/readback,local proofs,copy oracle and bounded caller replays.

O(B+F+R+V) time/space in retained bytes,fixups,records and visits. Each source
replay has its declared finite cap. No native target/endpoint/host operation.
"""
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib
from unicorn import arm64_const as A
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA,SOURCE,FIXUPS
from probe_adid_iokit_callers import Callers,caller_record,P,OUT,BUF,DEST,MASK32
from probe_adid_receiver import DONE
from probe_adid_startup import unpack_records


def read(name):return json.loads((ROOT/name).read_text())


def main():
    assertions=[]
    def check(condition,label):
        assert condition,label
        assertions.append(label)
    s=Adid();p=read('adid_iokit_caller_profiles.json');c=read('adid_iokit_caller_contracts.json');rows={r['fixture']['label']:r for r in p['profiles']};events={k:unpack_records(r) for k,r in rows.items()}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh provider identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_iokit_callers.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_iokit_callers.py').read_bytes()),'producer and recoverer source pins')
    for src in (p,c):
        for name,digest in src['dependencies'].items():check(sha((ROOT/name).read_bytes())==digest,'dependency '+name)
    run=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(SOURCE)],capture_output=True,check=True);check(run.stdout==FIXUPS.read_bytes(),'independent original fixup display')
    insns={}
    for i in p['original_instruction_records']:
        a=int(i['ea'],16);raw=s.read(a,4);d=next(CS.disasm(raw,a));insns[a]=raw
        check(raw.hex()==i['bytes'] and d.mnemonic==i['mnemonic'] and d.op_str==i['operands'],'fresh instruction '+i['ea'])
    for f in p['original_functions']:
        a,z=int(f['start'],16),int(f['end'],16);check(s.bounds(a)==(a,z) and sha(s.read(a,z-a))==f['sha256'],'fresh compiler range '+f['start'])
    for w in c['original_windows']:
        a,z=int(w['start'],16),int(w['end'],16);raw=s.read(a,z-a)
        check(s.bounds(a)==(a,z) and raw.hex()==w['bytes'] and sha(raw)==w['sha256'],'complete caller source '+w['start'])
        actual=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)];check(actual==w['instructions'],'caller decode '+w['start'])
    scan=c['whole_text_scan'];a=int(scan['address'],16);blob=s.read(a,scan['size_bytes']);check(sha(blob)==scan['sha256'] and len(blob)%4==0,'complete original text bytes')
    candidates=set();direct=[]
    words=[w for (w,) in struct.iter_unpack('<I',blob)]
    for ix,w in enumerate(words):
        pc=a+4*ix
        if ix and words[ix-1] in [0xd2800000|(v<<5)|17 for v in (0x2ea7,0xe41b)]:
            i=next(CS.disasm(blob[ix*4:ix*4+4],pc),None)
            if i is not None and i.mnemonic=='blraa' and i.op_str=='x8, x17':candidates.add(pc)
        if w&0x7c000000==0x14000000:
            off=w&0x3ffffff;off=off-(1<<26) if off&(1<<25) else off;target=pc+off*4
            if target in (0x1000208fc,0x10002af70):direct.append({'pc':hex(pc),'mnemonic':'bl' if w>>31 else 'b','target':hex(target)})
    check(len(words)==scan['four_byte_units'] and scan['decoded_instruction_count']+len(scan['undecoded_four_byte_units'])==len(words),'full text scan extent including undecoded words')
    check(candidates=={int(r['pc'],16) for r in scan['modifier_candidates']} and direct==scan['direct_helper_branches'],'independent raw-word candidate/direct scan')
    for u in scan['undecoded_four_byte_units']:
        pc=int(u['address'],16);raw=s.read(pc,4);check(raw.hex()==u['bytes'] and not list(CS.disasm(raw,pc)),'explicit undecoded source unit '+u['address'])
    for r in scan['modifier_candidates']:
        pc=int(r['pc'],16);raw=bytes.fromhex(r['window_bytes']);check(s.read(int(r['window_start'],16),len(raw))==raw and sha(raw)==r['window_sha256'],'candidate source '+r['pc'])
        for observation in r['observed_private_targets']:
            source=read(observation['source_file']);row=next(x for x in source['profiles'] if x['fixture']['label']==observation['example_profile']);check(observation['event'] in unpack_records(row),'fresh retained candidate observation '+r['pc'])
            for ptr in observation['matching_original_pointers']:check(s.decoded[int(ptr['address'],16)]==ptr,'candidate target pointer '+ptr['address'])
    collision=[r for r in s.decoded.values() if r.get('diversity') in ('0x2ea7','0xe41b','0xe258')];check(collision==c['modifier_collision_pointers'] and len(collision)==12,'three modifier families each have four original targets')
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain local proof '+proof['path'])
    witness=int(c['rejected_unconditional_helper_key']['address_u32'],16);original=(((0x3214ed72&~witness)-(0x3214ed73|(~witness&MASK32)))^0xb15299df)*0x0a42990d&MASK32
    check(witness&1 and original!=((witness^0x834674ac)*0x0a42990d&MASK32),'retained counterexample rejects unaligned simplification')
    total=0;helper_records=0;copy_bytes=0;method100_calls=0
    for label,row in rows.items():
        f=row['fixture'];visit=zlib.decompress(base64.b64decode(row['visited_original_instructions_zlib_base64']));h=hashlib.sha256()
        check(len(visit)==row['visited_original_instruction_count']*8,'visit extent '+label)
        for (pc,) in struct.iter_unpack('<Q',visit):h.update(struct.pack('<Q',pc));h.update(insns[pc])
        total+=len(visit)//8;check(h.hexdigest()==row['ordered_original_instruction_sha256'],'complete ordered original source '+label);check(row['steps']<=f['instruction_budget']+1,'finite hook cap '+label)
        if f.get('sequence_index',0)==0:check(row['private_buffers_before']['record64']==caller_record(f).hex(),'initial caller input '+label)
        for e in events[label]:
            if e['kind']=='original_selected_pointer_read':
                ptr=e['source_pointer'];actual=0x7c000000+ptr['import']['ordinal']*256 if ptr['bind'] else int(ptr['target'],16)
                check(e['size_bytes']==8 and s.decoded[int(e['address'],16)]==ptr and int(e['decoded_private_value_u64'],16)==actual,'original selected cell '+label+' '+e['pc'])
            if e['kind']=='original_caller_built_helper_record':
                helper_records+=1;address=int(e['address'],16);raw=bytes.fromhex(e['observed_bytes24']);word=struct.unpack_from('<I',raw)[0]
                if e['entry']=='0x1000208fc':
                    key=((address^0x08f753d6)*0x255e728d)&MASK32;check(word^key==0x25 and e['caller_return']=='0x100059548','original primary helper record '+label)
                else:
                    key=((address^0x834674ac)*0x0a42990d)&MASK32;check(address&1==0 and (word-key)&MASK32==0x10fd and e['caller_return']=='0x10005895c','aligned original Avp helper record '+label)
                check(e['callee_not_replaced'] is True,'original helper executed '+label)
        boundary=[e for e in events[label] if e['kind']=='original_method100_boundary'];models=[e for e in events[label] if e['kind']=='caller_method100_model'];method100_calls+=len(boundary)
        if boundary:
            e=boundary[0];args=[int(x,16) for x in e['args_x0_x7']];check(e['callsite']=='0x100058a1c' and args[:2]==[0x5804,100] and args[2]==args[4]==f.get('buffer',BUF) and args[3]==e['output_size_before_u64']==f['input_size'],'selector100 data ABI '+label)
            source=bytes.fromhex(row['private_buffers_before']['source_surrounding1056']);check(bytes.fromhex(e['input_bytes'])==source[16:16+f['input_size']],'original method100 input bytes '+label)
        if models:
            model=models[0];n=model['output_size_after_u64'];result=model['result_u32'];status=struct.unpack_from('<I',bytes.fromhex(row['private_buffers_after']['record64']),32)[0]
            check(model['buffer_unchanged'] and model['kext_transform_executed'] is False and status==(result+0x59248f)&MASK32,'method100 status reduction '+label)
            expected={}
            for start,key in [(BUF-16,'source_surrounding1056'),(DEST,'destination1024'),(OUT,'output4')]:expected.update({start+j:b for j,b in enumerate(bytes.fromhex(row['private_buffers_before'][key]))})
            writes=row['source_copy_writes'];copy_bytes+=len(writes)
            if result==0 and n:
                dest=f.get('destination',DEST);saved=[expected[BUF+j] for j in range(n)]
                for j,b in enumerate(saved):expected[dest+j]=b
                for j,b in enumerate(struct.pack('<I',(n+0x46d726)&MASK32)):expected[OUT+j]=b
                addresses=list(range(dest,dest+n)) if BUF>dest else list(range(dest+n-1,dest-1,-1))
                check([int(w['address'],16) for w in writes]==addresses,'exact copy order and extent '+label)
                check([w['value_u8'] for w in writes]==(saved if BUF>dest else list(reversed(saved))),'independent saved-byte overlap oracle '+label)
            else:check(not writes,'zero/error has no copy '+label)
            for start,key in [(BUF-16,'source_surrounding1056'),(DEST,'destination1024'),(OUT,'output4')]:
                actual=bytes.fromhex(row['private_buffers_after'][key]);check(actual==bytes(expected[start+j] for j in range(len(actual))),'complete private buffer oracle '+label+' '+key)
            check(row['stop_reason']=='returned_to_private_fixture','completed method100 continuation '+label)
    def kind(label,name):return [e for e in events[label] if e['kind']==name]
    def status(label,offset):return struct.unpack_from('<I',bytes.fromhex(rows[label]['private_buffers_after']['record64']),offset)[0]
    for label in ['avp100_null_count','avp100_null_destination','avp100_null_buffer','avp100_zero_size']:
        check(not kind(label,'original_caller_built_helper_record') and status(label,32)==0x588068,'zero/null guard avoids acquisition '+label)
    for label in ['avp100_failure_mainport','avp100_failure_no_service','avp100_failure_open']:
        check(not kind(label,'original_method100_boundary') and status(label,32)==0x588068,'acquisition failure avoids method100 '+label)
    check(status('primary_null_output',12)==0x587c8c and not kind('primary_null_output','original_caller_built_helper_record'),'encoded NULL primary output')
    for label in ('primary_literal_zero_field','primary_bad_basis'):check(rows[label]['stop_reason']=='unresolved_private_memory_boundary' and events[label][-1]['native_fault_inferred'] is False,'invalid private primary record '+label)
    check(status('primary_error',12)==0x587c93 and rows['primary_error']['private_buffers_after']['output4']=='1fa5a5a5','primary child error propagated')
    check(status('primary_identity',12)==0x587c85 and kind('primary_identity','original_caller_helper_return_record')[0]['bytes16'][8:16]=='8f245900','helper completion distinct from caller result')
    for label,expected_status,byte in [('primary_post_0x41_0x0',0x59248f,'1f'),('primary_post_0x40_0x527e14b6',0x587c85,'1f'),('primary_post_0x41_0x527e14b6',0x59248f,'20')]:
        check(status(label,12)==expected_status and rows[label]['private_buffers_after']['output4']==byte+'a5a5a5' and kind(label,'analyst_private_post_context_patch')[0]['native_state_or_writer_established'] is False,'explicit post-context control '+label)
    check(kind('primary_identity','original_caller_post_context')[0]['address']=='0x1002dcee0','distinct Avp context gate address')
    for label,row in rows.items():
        if not label.startswith('two_stage_'):continue
        es=events[label];matching=[e['name_string'] for e in es if e.get('name')=='_IOServiceMatching'];opens=[e for e in es if e.get('name')=='_IOServiceOpen']
        direct26=kind(label,'original_direct26_boundary_and_model');primary26=kind(label,'original_IOConnect_structure_boundary')
        check(matching==['AvpFairPlayDriver','com_apple_driver_FairPlayIOKit'] and [e['connection_output_cell'] for e in opens]==['0x1002dcee4','0x1002dcc84'],'ordered two-provider acquisition '+label)
        check(len(direct26)==len(primary26)==1 and direct26[0]['args_x0_x7'][:4:3]==['0x580a','0x60'] and primary26[0]['args_x0_x7'][0]=='0x5804' and primary26[0]['args_x0_x7'][3]=='0x10','distinct two-stage connection/framing '+label)
        check(es.index(direct26[0])<es.index(primary26[0]) and row['stop_reason']=='returned_to_private_fixture','Avp direct26 followed by primary descriptor26 '+label)
        expected=0x59248f if row['fixture']['direct26_mode']=='identity_success' else 0x587c93
        returned=struct.unpack_from('<I',bytes.fromhex(kind(label,'original_caller_helper_return_record')[0]['bytes16']),4)[0]
        check(returned==expected and status(label,12)==expected and row['private_buffers_after']['output4']=='1fa5a5a5','Avp-stage outcome retained despite independent primary-stage result '+label)
    check(not [e for e in events['avp100_warm_1'] if e.get('name')=='_IOServiceOpen'] and len(kind('avp100_warm_1','original_method100_boundary'))==1,'warm Avp cache still performs method100')
    check(not [e for e in events['primary_recovery_2'] if e['kind']=='hardware_modeled_API'] and len(kind('primary_recovery_2','original_caller_built_helper_record'))==1 and status('primary_recovery_2',12)==0x587c85,'warm primary helper remains distinct from outer context result')
    # Fresh replay uses the same declared API/PAC/vector models,not native APIs.
    replay_steps=0;replays=0;checkpoint=read('adid_peer_checkpoint.json')
    def same(q,label):
        nonlocal replay_steps,replays
        actual=q.run_continuation();reference=rows[label];replay_steps+=actual['steps'];replays+=1
        check(actual['stop_reason']==reference['stop_reason'] and actual['ordered_original_instruction_sha256']==reference['ordered_original_instruction_sha256'] and unpack_records(actual)==events[label] and q.buffers()==reference['private_buffers_after'] and q.copy_writes==reference['source_copy_writes'],'fresh complete source/event/state replay '+label)
    for label in ['primary_identity','primary_post_0x41_0x527e14b6','two_stage_identity_success_identity_success','two_stage_return_error_identity_success','avp100_identity','avp100_returned_size_0','avp100_overlap_above','avp100_overlap_below']:
        same(Callers(s,json.loads(json.dumps(rows[label]['fixture'])),checkpoint),label)
    for group,n in [('primary_recovery',3),('avp100_warm',2)]:
        q=Callers(s,json.loads(json.dumps(rows[group+'_0']['fixture'])),checkpoint)
        for j in range(n):
            if j:
                q.fixture=json.loads(json.dumps(rows[group+'_'+str(j)]['fixture']));q.steps=0;q.reason=None;q.records=[];q.visited=[];q.last_edge=None;q.copy_writes=[];q.initial_buffers=q.buffers()
                q.u.reg_write(A.UC_ARM64_REG_SP,q.sp);q.u.reg_write(A.UC_ARM64_REG_LR,DONE);q.u.reg_write(A.UC_ARM64_REG_PC,q.fixture['new_entry']);q.u.reg_write(A.UC_ARM64_REG_X0,P)
            same(q,group+'_'+str(j))
    compile=c['SDK_compile'];check(sha((ROOT/'adid_iokit_caller_layouts.c').read_bytes())==compile['source_sha256'] and sha((ROOT/'adid_iokit_caller_layouts.s').read_bytes())==compile['assembly_sha256'],'ABI source/output pins')
    with tempfile.TemporaryDirectory(prefix='adid-iokit-callers-') as directory:
        command=compile['command'][:-1]+[str(Path(directory)/'layouts.s')];run=subprocess.run(command,capture_output=True,check=True);check(not run.stderr and (Path(directory)/'layouts.s').read_bytes()==(ROOT/'adid_iokit_caller_layouts.s').read_bytes(),'fresh arm64e caller and method100 SDK compile')
    check(sha(Path(c['SDK_header']['path']).read_bytes())==c['SDK_header']['sha256'],'SDK header identity')
    original=read('interface_manifest.json')['inputs_preserved']
    for r in original:
        path=ROOT.parent/r['path'];check(path.stat().st_size==r['size_bytes'] and sha(path.read_bytes())==r['sha256'],'original input preserved '+r['path'])
    counts={'private_cases':len(rows),'original_instruction_records':len(insns),'original_compiler_ranges':len(p['original_functions']),'retained_original_visits':total,'caller_built_helper_records':helper_records,'method100_boundaries':method100_calls,'source_copy_bytes':copy_bytes,'SMT_unsat':len(c['proofs']),'complete_caller_windows':len(c['original_windows']),'text_four_byte_units':len(words),'undecoded_text_units':len(scan['undecoded_four_byte_units']),'modifier_candidates':len(candidates),'collision_pointers':len(collision),'two_stage_cases':4,'independent_replay_runs':replays,'independent_replay_steps':replay_steps,'SDK_compile_exit':0,'assertions':len(assertions)}
    result={'scope':__doc__,'verified_counts':counts,'checks':assertions,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_iokit_caller_checks.json').write_text(json.dumps(result,indent=2)+'\n')
    quality={'scope':'Caller records,two-stage provider correction,method100 size/copy and local state contracts;full goal active.','verified_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    descriptions=['Descriptive technical findings.','Report J1-J9 state dependencies and falsification boundaries.','Actual local source constructors and downstream interface progress;upstream/native goal remains open.','Six local proofs,aligned corollary and counterexample,byte-copy oracle and SDK widths.','Corrected early-boundary framing interpretation;split connection names,zero/error/overlap/status and post-state cases.','Fresh original bytes/fixups,source/event replays,SDK compile and original inputs.','Impact-labeled callers,real provider/response/rights,context writers and deeper protected operation/RPC boundaries.']
    for j,description in enumerate(descriptions,1):quality['QG'+str(j)]={'status':'pass_for_stated_increment','evidence':description}
    (ROOT/'adid_iokit_caller_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
