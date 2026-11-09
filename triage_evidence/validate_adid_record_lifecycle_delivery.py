#!/usr/bin/env python3
"""Fresh source, literal inventory, field/initialization oracles and replay.

O(B+F+R+V) time/space, bounded private hooks. Independent Capstone literal
reconstruction and byte-coverage oracles; replay shares frozen API/PAC models.
No native target, allocator, mmap, IOKit, Mach or target-file API executes.
"""
import base64
import hashlib
import json
import re
import struct
import subprocess
import zlib
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA,SOURCE,FIXUPS
from probe_adid_record_lifecycle import run_one,run_pipeline
from probe_adid_startup import unpack_records


def read(name):return json.loads((ROOT/name).read_text())


def main():
    assertions=[]
    def check(v,label):
        assert v,label
        assertions.append(label)
    s=Adid();p=read('adid_record_lifecycle_profiles.json');c=read('adid_record_lifecycle_contracts.json');rows={r['fixture']['label']:r for r in p['profiles']};events={k:unpack_records(r) for k,r in rows.items()};mask=(1<<64)-1
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh original slice identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_record_lifecycle.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_record_lifecycle.py').read_bytes()),'generator/recoverer pins')
    for a in (p,c):
        for name,digest in a['dependencies'].items():check(sha((ROOT/name).read_bytes())==digest,'dependency '+name)
    run=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(SOURCE)],capture_output=True,check=True);check(run.stdout==FIXUPS.read_bytes(),'independent original fixup display')
    instructions={}
    for i in p['original_instruction_records']:
        pc=int(i['ea'],16);raw=s.read(pc,4);d=next(CS.disasm(raw,pc));instructions[pc]=raw;check(raw.hex()==i['bytes'] and (d.mnemonic,d.op_str)==(i['mnemonic'],i['operands']),'original instruction '+i['ea'])
    for f in p['original_functions']:
        a,z=int(f['start'],16),int(f['end'],16);check(s.bounds(a)==(a,z) and sha(s.read(a,z-a))==f['sha256'],'complete compiler range '+f['start'])
    for w in c['original_windows']+c['allocation_functions']:
        a,z=int(w['start'],16),int(w['end'],16);raw=s.read(a,z-a);ds=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)];check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'] and ds==w['instructions'],'complete original source '+w['start'])
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'proof pin '+proof['path']);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain local proof '+proof['path'])
    inv=c['whole_text_literal_inventory'];a=int(inv['start'],16);raw=s.read(a,inv['size_bytes']);check(sha(raw)==inv['sha256'] and len(raw)//4==inv['four_byte_units'],'whole original text extent')
    cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM);cs.skipdata=True;regs={};hits=[];units=0;undecoded=0
    for i in cs.disasm(raw,a):
        units+=i.size//4
        if i.id==0:undecoded+=1
        word=struct.unpack('<I',i.bytes)[0] if i.size==4 else 0;op=word&0xff800000
        if op not in (0xd2800000,0x92800000,0xf2800000):regs={};continue
        m=re.match(r'x(\d+), #(-?(?:0x[0-9a-f]+|\d+))(?:, lsl #(0x[0-9a-f]+|\d+))?$',i.op_str);check(m is not None,'Capstone MOV-wide operand '+hex(i.address));reg=m[1];value=int(m[2],0)&mask
        if i.mnemonic=='mov':regs[reg]=(value,[i.address])
        elif i.mnemonic=='movk' and reg in regs:
            old,pcs=regs[reg];shift=int(m[3] or '0',0);regs[reg]=((old&~(65535<<shift))|(value<<shift),pcs+[i.address])
        if reg in regs:
            v,pcs=regs[reg]
            if len(pcs)==4 and v>>32 in [0x9053e834,0xd2e521bd,0xa731fc27,0x6fac17cb,0x2d1ade42,0x58ce03d8]:hits.append((hex(pcs[0]),hex(v),[hex(x) for x in pcs]))
    check(units==inv['four_byte_units'] and hits==[(h['start'],h['value_u64'],h['member_pcs']) for h in inv['literal_hits']],'independent full-text Capstone literal-family reconstruction')
    check(len(c['direct_field98_literal_sites'])==6 and {h['literal_start'] for h in c['direct_field98_literal_sites']}=={'0x100120088','0x10013f984','0x10019c2f8','0x10019cad4','0x10019f640','0x10019fab4'},'six direct literal-based field98 sites only')
    counts={'source_visits':0,'constructor_cases':0,'constructor_completions':0,'constructor_failures':0,'outer_defined_bytes':0,'nested_defined_bytes':0,'object_writes':0,'allocator_cases':0,'allocator_API_boundaries':0,'encode_cases':0,'decode_cases':0,'field_absent_cases':0}
    for label,r in rows.items():
        f=r['fixture'];mode=f['mode'];es=events[label];packed=zlib.decompress(base64.b64decode(r['visited_original_instructions_zlib_base64']));h=hashlib.sha256();check(len(packed)==r['visited_original_instruction_count']*8,'visit extent '+label)
        for (pc,) in struct.iter_unpack('<Q',packed):h.update(struct.pack('<Q',pc));h.update(instructions[pc])
        counts['source_visits']+=len(packed)//8;check(h.hexdigest()==r['ordered_original_instruction_sha256'] and r['steps']<=f['instruction_budget']+1,'complete ordered source and finite cap '+label)
        counts['object_writes']+=len(r['original_object_writes']);check(not any(e.get('name','').startswith('_IO') or e.get('name')=='_malloc' for e in es),'no IOKit/imported malloc boundary '+label)
        if mode=='constructor':
            counts['constructor_cases']+=1;failed=f.get('cold_first') or f.get('cold_second');check(r['stop_reason']==('constructor_failure_exit' if failed else 'constructor_before_publication'),'bounded constructor outcome '+label)
            counts['constructor_failures' if failed else 'constructor_completions']+=1;want=[];key=f['key_u64'];tag=0x61aec521 if key==mask else 0x61aec522 if key>=0xfffffffffffffff0 else 0x61aec520
            def write(obj,off,size,value,pc):want.append((obj,off,size,value,pc))
            outer=int(r['object_addresses'].get('outer','0'),16);nested=int(r['object_addresses'].get('nested','0'),16)
            if outer:
                for off,size,value,pc in [(8,4,0x46d726,0x10019c714),(16,8,0x37ae849540968152,0x10019c728),(24,4,0x46d726,0x10019c72c),(32,8,0,0x10019c730),(56,4,0x16911135,0x10019c73c),(92,4,f.get('outer_flag',0),0x10019c744),(0,8,0x6fac17cb61e34e69,0x10019c758),(0,8,(nested+0x6fac17cb61e34e69)&mask,0x10019c7d8)]:write('outer',off,size,value,pc)
            if nested:
                vmm=int(f.get('VMM_status',0)==0 and f.get('VMM_value',0)==1)
                for off,size,value,pc in [(8,8,key^0xda8ca8cae5dfbd2d,0x10019c82c),(0,4,tag,0x10019c8d0),(16,8,0xda8ca8cae5dfbd2d,0x10019c8fc),(96,4,0x46d726,0x10019c920),(24,4,0x46d726,0x10019c93c),(132,4,0x46d726,0x10019c958),(88,8,0x37ae849540968152,0x10019c984),(160,4,(f['record_uid']+0x46d726)&0xffffffff,0x10019c9a4),(164,4,0x46d726+vmm,0x10019ca90),(136,4,0x46d726,0x10019caac),(144,8,0x37ae849540968152,0x10019cac8),(152,8,0xda8ca8cae5dfbd2d,0x10019cae8),(168,8,0x6fac17cb61e34e69,0x10019cb14)]:write('nested',off,size,value,pc)
            check([(w['object'],w['offset_bytes'],w['size_bytes'],int(w['value'],16),int(w['pc'],16)) for w in r['original_object_writes']]==want,'independent complete constructor store oracle '+label)
            reconstructed={k:bytearray.fromhex(v) for k,v in r['object_initial_bytes'].items()};defined={k:set() for k in reconstructed}
            for w in r['original_object_writes']:
                k=w['object'];off=w['offset_bytes'];size=w['size_bytes'];check(reconstructed[k][off:off+size].hex()==w['before_bytes'],'exact prior bytes '+label+' '+w['pc']);reconstructed[k][off:off+size]=int(w['value'],16).to_bytes(size,'little');defined[k].update(range(off,off+size))
            check({k:v.hex() for k,v in reconstructed.items()}==r['object_final_bytes'],'all initialized and untouched bytes '+label)
            if nested:check(len(defined['outer'])==40 and len(defined['nested'])==76,'partial initialization byte coverage '+label)
            counts['outer_defined_bytes']+=len(defined.get('outer',[]));counts['nested_defined_bytes']+=len(defined.get('nested',[]))
            requests=[e for e in es if e['kind']=='original_allocation_request'];returns=[e for e in es if e['kind']=='original_allocation_return'];check([int(e['registers']['x0'],16) for e in requests]==([96] if f.get('cold_first') else [96,176]),'original requested byte extents '+label)
            edges=[e for e in es if e['kind']=='PAC_bypassed_edge' and e['pc'] in ['0x10019c654','0x10019c7cc']];check(len(edges)==len(requests) and all(e['target']=='0x1000621d4' and e['modifier']=='0xd825' for e in edges),'constructor protected allocation target '+label)
            check(len(returns)==len(requests) and all((int(e['result_address'],16)==0 or int(e['result_address'],16)%16==0) for e in returns),'allocation result extent/alignment observations '+label)
        elif mode=='allocator':
            counts['allocator_cases']+=1;maps=[e for e in es if e.get('name')=='_mmap'];counts['allocator_API_boundaries']+=len(maps)
            if maps:
                check(r['stop_reason']=='unreviewed_mapping_guard' and len(maps)==1,'explicit unexecuted mapping boundary '+label);e=maps[0];args=[int(v,16) for v in e['args_x0_x7']];site=e['callsite'];pc='0x100267a84' if site=='0x100267b1c' else '0x100267c18';b=next(e for e in es if e['kind']=='original_allocation_layer_boundary' and e['pc']==pc);x={k:int(v,16) for k,v in b['registers'].items()};n=x['x9'];align=x['x8'];normalized=max(32,(f['requested_bytes']+31)&~15)
                check(n==normalized and align>0 and align&(align-1)==0,'source normalized extent and power-of-two alignment '+label)
                want=((n+align+(62 if site=='0x100267b1c' else 95))&mask)&((-align)&mask);check(args[:6]==[0,want,3,0x1002,0xffffffff,0] and e['native_API_executed'] is False,'exact anonymous mapping ABI '+label)
            else:
                check(r['stop_reason']=='returned_to_private_fixture','bounded allocation return '+label);value=int(r['return_x0_u64'],16);zero=f.get('cold_first') or f['requested_bytes']>=0xffffffffffffff7f
                check(value==0 if zero else value!=0 and value%16==0 and any(int(a,16)<=value<int(a,16)+n for a,n in r['private_mappings_final']),'declared finite allocation return '+label)
        elif mode=='encode':
            counts['encode_cases']+=1;present=f.get('field_present',1)
            if present:check(r['stop_reason']=='local_field_encode_complete' and r['local_output8']==bytes(b^0x73 for b in f['value_u64'].to_bytes(8,'big')).hex(),'independent local serializer byte oracle '+label)
            else:counts['field_absent_cases']+=1;check(r['stop_reason']=='local_field_absent_boundary','encoder presence guard '+label)
            check(r['original_object_writes']==[] and r['object_initial_bytes']==r['object_final_bytes'],'serializer only reads nested object '+label)
        elif mode=='decode':
            counts['decode_cases']+=1;present=f.get('field_present',1);initial=bytearray.fromhex(r['object_initial_bytes']['nested']);value=int.from_bytes(bytes((b-0x19)&255 for b in bytes.fromhex(f['local_input8'])),'big')^0xda8ca8cae5dfbd2d
            if present:
                initial[152:160]=value.to_bytes(8,'little');check(r['stop_reason']=='local_field_decode_complete' and [(w['pc'],w['offset_bytes'],w['size_bytes'],int(w['value'],16)) for w in r['original_object_writes']]==[('0x10013f998',152,8,value)],'independent parser and sole field store '+label)
            else:counts['field_absent_cases']+=1;check(r['stop_reason']=='local_field_absent_boundary' and not r['original_object_writes'],'parser presence guard '+label)
            check(initial.hex()==r['object_final_bytes']['nested'],'complete parser object byte extent '+label)
        else:
            check(mode=='update' and r['stop_reason']=='returned_to_private_fixture','original callback completion in explicit publication pipeline '+label);pub=[e for e in es if e['kind']=='analyst_publication_of_source_constructed_record'];check(len(pub)==1 and pub[0]['object_fields_patched'] is False and pub[0]['native_publication_established'] is False,'publication fixture and unchanged source-constructed fields '+label)
            value=struct.unpack('>IIIQQ',bytes.fromhex(f['payload_hex']))[-1];check([(w['pc'],w['object'],w['offset_bytes'],int(w['value'],16)) for w in r['original_object_writes']]==[('0x10019c310','nested',152,value^0xda8ca8cae5dfbd2d)],'source-constructed record receives request value '+label)
            check([(e['callsite'],e['payload_bytes']) for e in es if e.get('name')=='_xpc_dictionary_set_data']==[('0x1000aa9fc','00000000')] and [e['callsite'] for e in es if e.get('name')=='_xpc_dictionary_send_reply']==['0x1000aaa70'],'pipeline payload and existing XPC emission '+label)
    a,b,d=[rows[x] for x in ['pipeline_constructor','pipeline_original_callback_update','pipeline_field_encode']];check(a['object_final_bytes']==b['object_initial_bytes'] and b['object_final_bytes']['nested']==d['object_initial_bytes']['nested'],'exact source-object continuity across declared pipeline')
    replay_steps=0;replay_count=0;ck=read('adid_driver_dispatch_frame.json')
    for label in ['constructor_key_-16','constructor_uid501','constructor_vmm_error','constructor_cold_second','allocator_0xffffffff','allocator_0xffffffffffffff80','encode_0x8000000000000000','decode_arbitrary_bytes','encode_absent']:
        q,actual=run_one(s,rows[label]['fixture'],ck);replay_steps+=actual['steps'];replay_count+=1;check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and unpack_records(actual)==events[label] and actual['original_object_writes']==rows[label]['original_object_writes'] and actual['object_final_bytes']==rows[label]['object_final_bytes'],'fresh complete fragment/function replay '+label)
    for q,actual in run_pipeline(s,ck):
        label=actual['fixture']['label'];replay_steps+=actual['steps'];replay_count+=1;check(actual['ordered_original_instruction_sha256']==rows[label]['ordered_original_instruction_sha256'] and unpack_records(actual)==events[label] and actual['object_final_bytes']==rows[label]['object_final_bytes'] and actual['original_object_writes']==rows[label]['original_object_writes'],'fresh full declared pipeline stage '+label)
    for r in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/r['path'];check(path.stat().st_size==r['size_bytes'] and sha(path.read_bytes())==r['sha256'],'original input preserved '+r['path'])
    verified={'private_cases':len(rows),**counts,'original_instruction_records':len(instructions),'original_compiler_ranges':len(p['original_functions']),'text_four_byte_units':units,'undecoded_text_units':undecoded,'literal_family_hits':len(hits),'direct_field98_literal_sites':len(c['direct_field98_literal_sites']),'new_SMT_unsat':len(c['proofs']),'complete_windows':len(c['original_windows']),'complete_allocation_functions':len(c['allocation_functions']),'independent_replay_runs':replay_count,'independent_replay_steps':replay_steps,'assertions':len(assertions)}
    (ROOT/'adid_record_lifecycle_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':verified,'checks':assertions,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    q={'scope':'Source constructor/allocation/local field consumers and explicit constructed-node publication pipeline; native lifecycle and full goal incomplete.','verified_counts':verified,'native_target_executed':False,'full_goal_complete':False}
    texts=['Descriptive technical findings.','Report R1-R10 identify assumptions,dependencies and probes.','Constructor,allocation layers,local field consumers and explicit pipeline covered; native predecessors/publication/persistence/driver chain unknown.','Exact byte extents,u32/u64 arithmetic,six full-domain local proofs and independent byte/store/rounding oracles.','Cold contexts,partial initialization,overflow/presence guards,distinct byte epochs and artificial publication separated.','Fresh original bytes/fixups,full-text literal reconstruction and twelve source replays; original inputs preserved.','Impact-labeled native publication/free/locking,persistence epoch transforms,value readers and driver/IPC pairing.']
    for i,t in enumerate(texts,1):q['QG'+str(i)]={'status':'pass_for_stated_increment','evidence':t}
    (ROOT/'adid_record_lifecycle_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps(verified))


if __name__=='__main__':main()
