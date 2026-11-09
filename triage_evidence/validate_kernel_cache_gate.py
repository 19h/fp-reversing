#!/usr/bin/env python3
"""Original gate writers, counter metadata, adaptive quota and source-state joins.
O(image+words+windows+visits+RAM+effects), O(image+source+RAM+journals).
Finite input/state oracles and bounded SMT; no native process/VM/IPC/lock effects.
"""
import json,struct
from collections import Counter
from z3 import BitVec,BitVecVal,ZeroExt,SignExt,Extract,If,ULE,ULT,UGT,And,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from recover_kernel_cache_gate import scan
from replay_rpc502_vm_handoff import decode
from replay_kernel_zone_startup import Replay as BootReplay
from replay_kernel_cache_gate import Replay
P='kernel_cache_gate';R=0x6500000000;SIZE=0x100000;SP=R+0xf0000;HALT=R+0xe0000;THREAD=R+0x2c000;PENDING=R+0xb4000;ZONE=0xfffffe000caec680;ARRAY=0xfffffe000caeb480;GATE=0xfffffe000ca92380;FREE=0xfffffe000cb510e0;RESERVED=0xfffffe000cb2a2b8;STATS=R+0xb1000;CACHE=R+0xb2000;PROC=R+0x86000;KERNPROC=R+0x82000;PAGE=R+0xd0000;META=R+0xc0000;BITMAP=R+0xc1000;INDEX=PAGE>>14;HEADBASE=0xfffffe000ca8c000;U=(1<<32)-1

def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def put(b,o,n,x):b[o:o+n]=x.to_bytes(n,'little')
def ticket_cycle(word):
 assert(word>>24)==((word>>16)&255);return(word&65535)|((((word>>16)+1)&255)<<16)|((((word>>24)+1)&255)<<24)
def plan(c):
 mode=c['mode'];out=[(THREAD+0x1b8,bytes(2)),(THREAD+0x1c0,struct.pack('<Q',PENDING)),(THREAD+0x1c8,bytes(4)),(PENDING,bytes(80))]
 if mode=='publication':out.append((0xfffffe0007f8c250,struct.pack('<Q',KERNPROC)))
 elif mode=='policy':
  out.extend([(0xfffffe000caeb600,bytes(8)),(FREE,struct.pack('<I',c.get('free',100))),(RESERVED,struct.pack('<I',c.get('reserved',50)))])
  if 'gate'in c:out.append((GATE,bytes([c['gate']])))
  out.append((ZONE+0x74,struct.pack('<I',c.get('events',0))))
  if 'quota'in c:out.append((ZONE+0x7c,struct.pack('<H',c['quota'])))
  if 'prior_score'in c:out.append((ZONE+0x78,struct.pack('<I',c['prior_score'])))
  out.extend([(ZONE+0x84,struct.pack('<I',10)),(ZONE+0x8c,struct.pack('<I',c.get('capacity',1)))])
 elif mode=='cursor':out.append((STATS+0x18,struct.pack('<I',c['cursor'])))
 else:out.extend([(PAGE,bytes(16384)),(PAGE+16384,b'\xa5'),(ZONE+0x9c,struct.pack('<I',INDEX)),(ZONE+0xa8,struct.pack('<I',48)),(ZONE+0xb0,bytes(4)),(0xfffffe0007e66f00,struct.pack('<Q',META-INDEX*16)),(0xfffffe0007e66e70,struct.pack('<Q',BITMAP)),(META,struct.pack('<HHIII',0x1018,16,0,0,(ZONE+0x9c-(HEADBASE-4))>>2)),(BITMAP,struct.pack('<Q',((1<<64)-1)^((1<<16)-1)))])
 return out

def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());boot=json.loads((ROOT/'kernel_zone_startup_profiles.json').read_text())['cases'][0];counts=Counter();totals=Counter();summaries=[];proofs=[]
 for o,s in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
  assert all(o[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==25 and sum(len(f['instructions'])for f in src['functions'])==3944
 for f in src['functions']:
  a=int(f['start'],16);raw=im.k.read(a,int(f['end'],16)-a);assert raw.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==f['instructions'];counts['original_complete_functions_recaptured']+=1
 assert scan(im)==src['gate_reference_scan'];sc=src['gate_reference_scan'];assert sc['instruction_words']==15490987 and len(sc['page_ADRP_hits'])==1441 and len(sc['resolved_syntactic_memory_references'])==12 and len(sc['direct_calls'])==3 and sc['arbitrary_indirect_reference_completeness_established']is False;counts['full_collection_instruction_words_scanned']=sc['instruction_words'];counts['original_ADRP_windows_recaptured']=1441;counts['resolved_syntactic_gate_memory_sites_recaptured']=12
 assert len([e for e in sc['resolved_syntactic_memory_references']if e['mnemonic']=='strb'])==3 and not any(e['pc']=='0xfffffe000bd65024'for e in sc['resolved_syntactic_memory_references']);counts['store_sites_and_unrelated_offset_false_positive_separated']=1
 for e in src['counter_metadata']:
  a=int(e['record_address'],16);assert im.k.read(a,80).hex()==e['bytes80_hex'];fs=e['fields']
  for key in['argument','name','handler','format','description_pointer']:assert im.pointer(int(fs[key]['slot'],16))==fs[key]
  for key,ptr in[('name_text','name'),('format_text','format'),('description','description_pointer')]:assert im.k.read(int(fs[ptr]['target'],16),256).split(b'\0')[0].decode()==fs[key]
  assert any(s['name']=='_sysctl_handle_int'for s in fs['handler_symbols'])and im.k.symbols([int(fs['handler']['target'],16)])[fs['handler']['target']]==fs['handler_symbols']and fs['argument']['target']==e['counter']and fs['format_text']=='IU';counts['original_counter_registration_records_fixups_and_labels_recaptured']+=1
 assert[(e['counter'],e['fields']['name_text'])for e in src['counter_metadata']]==[(hex(FREE),'page_free_count'),(hex(RESERVED),'vm_page_free_reserved')]
 for e in src['gate_related_fixup_references']:assert im.pointer(int(e['pointer']['slot'],16))==e['pointer']and im.k.read(int(e['container_start'],16),64).hex()==e['container64_hex'];counts['authenticated_policy_callback_reference_recaptured']+=1
 for e in src['policy_parameter_file_bytes']:assert im.k.read(int(e['address'],16),len(e['bytes_hex'])//2).hex()==e['bytes_hex'];counts['policy_parameter_file_bytes_recaptured']+=1
 for e in src['other_zone_self_file_words']:assert int(e['address'],16)==ARRAY+192*e['identifier']and im.k.read(int(e['address'],16),8).hex()==e['bytes8_hex'];counts['other_zone_file_self_words_recaptured']+=1
 assert src['gate_file_byte_hex']==im.k.read(GATE,1).hex()=='ff'and src['gate_native_value_observed']is False
 for a,name in[(0xfffffe000c2b9748,'_proc_find'),(0xfffffe0007f8c250,'_kernproc'),(0xfffffe000bd5d120,'_thread_call_enter1')]:assert any(e['name']==name for e in src['publication_and_followup_exact_symbols'][hex(a)])
 free=BitVec('free_pages32',32);reserved=BitVec('reserved_pages32',32);gate=BitVec('gate8',8);q=BitVec('quota16',16);bound=BitVec('bound16',16);wide=ZeroExt(16,q);candidate=If(q==0,BitVecVal(2,32),((3*wide+2)>>1)&65535);grown=If(ULT(candidate,ZeroExt(16,bound)),candidate,ZeroExt(16,bound))
 qs=[('unsigned_page_threshold_all_u32',None,ULE(free,reserved),ULE(ZeroExt(32,free),ZeroExt(32,reserved))),('negative_byte_sentinel_all_u8',None,SignExt(24,gate)<0,Extract(7,7,gate)==1),('admitted_quota_growth_is_bounded_and_increases',And(ULT(q,bound),ULE(bound,32767)),And(UGT(grown,wide),ULE(grown,ZeroExt(16,bound))),True)]
 for name,domain,left,right in qs:
  sol=Solver()
  if domain is not None:sol.add(domain)
  sol.add(left!=right);assert sol.check()==unsat;proofs.append({'name':name,'domain':None if domain is None else str(domain),'query':sol.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1
 freshboot=BootReplay(im,boot).run();rows=prof['cases'];assert len(rows)==20
 def image_bytes(a,n,g):return bytes(g.get(a+k,im.logical_page((a+k)&~4095)[(a+k)&4095])for k in range(n))
 for j,r in enumerate(rows):
  c=r['configuration'];mode=c['mode'];tr=r['initial_state_transfer'];selfparent=tr['path']==P+'_profiles.json';idx=tr['case'];assert tr['path']in[P+'_profiles.json','kernel_zone_startup_profiles.json']and (0<=idx<j if selfparent else idx==0);parent=rows[idx]if selfparent else boot;base=decode(parent['final_private_RAM']);assert decode(tr)==base and all(r[k]is False for k in FLAGS)and r['private_RAM']=={'address':hex(R),'size_bytes':SIZE,'initial_byte':0};counts['exact_prior_full_RAM_handoffs_checked']+=1
  initial=bytearray(base);g={int(e['address'],16)+k:b for e in parent['final_image_globals']for k,b in enumerate(bytes.fromhex(e['bytes_hex']))};inherited=r['initial_image_fixtures'][:len(parent['final_image_globals'])];assert[{k:e[k]for k in['address','bytes_hex']}for e in inherited]==parent['final_image_globals'];counts['exact_prior_image_global_handoffs_checked']+=1
  assert[(int(e['address'],16),bytes.fromhex(e['after_hex']))for e in r['memory_overlays']]==plan(c);private=[];image=[]
  for e in r['memory_overlays']:
   a=int(e['address'],16);b=bytes.fromhex(e['after_hex'])
   if R<=a<a+len(b)<=R+SIZE:before=bytes(initial[a-R:a-R+len(b)]);initial[a-R:a-R+len(b)]=b;private.append({'address':hex(a),'bytes_hex':b.hex()})
   else:before=image_bytes(a,len(b),g);g.update({a+k:v for k,v in enumerate(b)});image.append({'address':hex(a),'bytes_hex':b.hex()})
   assert before.hex()==e['before_hex'];counts['explicit_input_patch_before_images_checked']+=1
  assert r['initial_private_fixtures']==private and[{k:e[k]for k in['address','bytes_hex']}for e in r['initial_image_fixtures'][len(inherited):]]==image;counts['exact_declared_input_plans_checked']+=1
  regs=['0x0']*31;regs[30]=hex(HALT);entry={'publication':0xfffffe000c266258,'policy':0xfffffe000bd7b938,'cursor':0xfffffe000bd76a6c,'allocator':0xfffffe000bcc24a4}[mode]
  if mode=='cursor':regs[:3]=[hex(ZONE),'0x0',hex(STATS)]
  if mode=='allocator':regs[:4]=['0x2c','0x0','0x0','0x1']
  assert r['entry_PC']==hex(entry)and r['entry_SP']==hex(SP)and r['entry_registers31']==regs and r['entry_NZCV']=='0x40000000'and r['entry_Q_registers32']==['0x0']*32 and r['private_system_register_fixtures']==[{'register':'TPIDR_EL1','value':hex(THREAD)}];counts['declared_new_call_ABI_epochs_checked']+=1
  z0=bytearray(image_bytes(ZONE,192,g));z=bytes.fromhex(r['final_zone192_hex']);wantz=bytearray(z0);wantstats=bytearray(initial[STATS-R:STATS-R+32]);wantcache=bytearray(initial[CACHE-R:CACHE-R+64]);gate0=image_bytes(GATE,1,g)[0];wantgate=gate0;models=r['API_models'];expectedmodels=[];globalchanges={}
  if mode=='publication':
   present=c.get('process_present',True);proc=PROC if present else 0;wantgate=0;globalchanges={0xfffffe000cb51668:struct.pack('<Q',proc),0xfffffe000ca92370:struct.pack('<I',1),0xfffffe000cb81100:b'\x01'};assert r['boundary']['kind']=='before_original_PID1_followup'and r['boundary']['registers31'][:2]==[hex(proc),'0x0'];expectedmodels=[('declared_initial_setup_object',THREAD),('declared_proc_find_PID1',proc)]
   assert models[0]['arguments8'][:4]==['0x0','0x0',hex(KERNPROC),'0x2']and models[1]['arguments8'][0]=='0x1';gw=[e for e in r['source_writes']if e['address']==hex(GATE)];assert len(gw)==1 and gw[0]['pc']==('0xfffffe000c2662bc'if present else'0xfffffe000c2662f0')and gw[0]['after_hex']=='00';counts['original_PID1_lookup_publication_and_both_gate_clear_branches_checked']+=1
  elif mode=='policy':
   if gate0&128:counts['negative_gate_sentinel_preserves_policy_state_checked']+=1
   else:
    wantgate=int(c.get('free',100)<=c.get('reserved',50));emptymin=val(z0,0x6c,4);fullmin=val(z0,0x64,4);put(wantz,0x6c,4,val(z0,0x4c,4));put(wantz,0x70,4,((3*val(z0,0x70,4)+(emptymin<<8))&U)>>2);put(wantz,0x64,4,val(z0,0x48,4));put(wantz,0x68,4,((3*val(z0,0x68,4)+(fullmin<<8))&U)>>2)
    cpu=val(image_bytes(0xfffffe0007e66f38,4,g),0,4);score=(((((val(z0,0x74,4)<<8)&U)//(15*cpu))+3*val(z0,0x78,4))&U)>>2;q0=val(z0,0x7c,2);limit=val(z0,0x7e,2);high=val(im.k.read(0xfffffe0007e66e30,4),0,4);low=val(im.k.read(0xfffffe0007e66e34,4),0,4);newq=q0;flags=val(z0,0x3c,4)
    if val(z0,0x8c,4)>=val(z0,0x84,4):
     if q0:newq=0;flags|=4;counts['original_capacity_forces_quota_zero_checked']+=1
    elif q0<limit and score>high:newq=min(2 if not q0 else((3*q0+2)>>1)&65535,limit);score=((high+low)&U)>>1;counts['original_quota_growth_and_bound_clamp_checked']+=1
    elif q0 and score<=low:newq=q0-1;flags|=4;score=((high+low)&U)>>1;counts['original_low_score_quota_decrement_checked']+=1
    put(wantz,0x7c,2,newq);put(wantz,0x3c,4,flags);put(wantz,0x74,4,0);put(wantz,0x78,4,score)
    for o in[0x60,0x80]:put(wantz,o,4,ticket_cycle(val(z0,o,4)))
    if flags&4:expectedmodels=[('declared_thread_call_enter1',0)];assert models[0]['arguments8'][:2]==['0xfffffe000cb7f1f0','0x0'];counts['original_followup_enqueue_request_checked']+=1
    for addr in[0xfffffe000bd0ae78,0xfffffe000bd0aab4,0xfffffe000bd0ab18]:assert sum(v['pc']==hex(addr)for v in r['source_visits'])==1;counts['original_uncontended_lock_helper_entries_checked']+=1
    counts['original_unsigned_page_threshold_and_filtered_policy_state_checked']+=1
    if j==14:assert idx==8 and q0==newq==2 and score==528;counts['source_produced_quota_hysteresis_cycle_checked']+=1
  elif mode=='cursor':
   step=c['step'];expectedmodels=[('declared_cursor_step_result',step)];assert models[0]['arguments8'][:4]==['0xfffffe000cb7f2d0','0xfffffe000cb7f2f8','0x2','0x8'];put(wantstats,0x18,4,((c['cursor']+step)&U)%val(z0,0x3a,2));counts['original_opaque_step_cursor_modulo_ABI_checked']+=1
  else:
   assert not any(a in[GATE,ZONE+0x7c]for a,_ in plan(c))and selfparent;counts['source_produced_gate_and_quota_consumed_without_overrides_checked']+=1
   active=gate0==0
   put(wantz,0x80,4,ticket_cycle(val(z0,0x80,4)))
   if val(z0,0x7c,2):put(wantz,0x60,4,ticket_cycle(val(z0,0x60,4)));put(wantcache,0,4,ticket_cycle(val(wantcache,0,4)))
   if active:
    put(wantz,0xa8,4,32);put(wantstats,0,8,256);put(wantstats,0x18,4,31);put(wantcache,4,2,15);assert r['boundary']['kind']=='original_allocator_call_returned'and r['boundary']['registers31'][0]==hex(PAGE+31*256)and r['final_element256_hex']=='00'*256 and r['final_metadata16_hex']==struct.pack('<HHIII',0x1018,32,0,0,(ZONE+0x9c-(HEADBASE-4))>>2).hex()and r['final_bitmap8_hex']==struct.pack('<Q',((1<<64)-1)^((1<<32)-1)).hex();counts['original_publication_policy_to_page_fill_and_constructor_return_join_checked']+=1
    obj=PAGE+31*256;covered=set()
    for e in r['source_reads']:
     a=int(e['address'],16)
     if 0xfffffe000bc9d9c0<=int(e['pc'],16)<0xfffffe000bc9daa0 and obj<=a<obj+256:assert a+e['size_bytes']<=obj+256;covered.update(range(a,a+e['size_bytes']))
    assert covered==set(range(obj,obj+256));counts['writer_join_complete_256byte_zero_check_coverage_checked']+=1
   else:assert gate0==1 and r['boundary']['kind']=='before_original_zone_fallback'and r['final_thread_nesting']==1 and r['final_metadata16_hex']==initial[META-R:META-R+16].hex()and r['final_bitmap8_hex']==initial[BITMAP-R:BITMAP-R+8].hex();counts['source_produced_low_memory_gate_to_held_fallback_join_checked']+=1
   assert models==[];counts['allocator_join_has_no_whole_lock_refill_or_allocator_model_checked']+=1
  globalchanges[GATE]=bytes([wantgate]);assert r['final_gate_u8']==wantgate and z==bytes(wantz)and r['final_statistics32_hex']==bytes(wantstats).hex()and r['final_cache64_hex']==bytes(wantcache).hex();counts['independent_full_zone_gate_statistics_cache_oracles_checked']+=1
  changes={a+k:b for a,raw in globalchanges.items()for k,b in enumerate(raw)}
  for e in r['final_image_globals']:
   a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);expect=z if a==ZONE else bytes(changes.get(a+k,image_bytes(a+k,1,g)[0])for k in range(len(b)));assert b==expect,(j,hex(a))
  assert[(m['symbol'],int(m['return_value'],16))for m in models]==expectedmodels and not any('lock'in m['symbol']for m in models);counts['no_whole_lock_model_checked']+=1
  for k,m in enumerate(models):
   want=[hex(((i+1)*0x123456789abcdef)^((k+1)*0x8b3dc651))for i in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and m['native_effects_executed']is False and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0);counts['declared_process_step_and_enqueue_clobber_models_checked']+=1
  if mode in['policy','cursor']or r['boundary']['kind']=='original_allocator_call_returned':assert r['boundary']['registers31'][18:]==regs[18:]and r['boundary']['SP']==hex(SP)and r['final_thread_nesting']==0;counts['original_return_ABI_and_balanced_thread_nesting_checked']+=1
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_dynamic_original_instruction_recaptured']+=1
  totals.update(Replay(im,r).run());summaries.append({'case':j,'mode':mode,'visits':len(r['source_visits']),'gate':r['final_gate_u8'],'quota':val(z,0x7c,2),'score':val(z,0x78,4),'boundary':r['boundary']['kind']});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=20,functions=25,captured_instructions=3944)
 deps=[P+'_source.json',P+'_profiles.json','kernel_zone_startup_profiles.json','recover_'+P+'.py','replay_'+P+'.py','replay_kernel_zone_startup.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','recover_kernel_send_right_lifecycle.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_startup_producer_replay':freshboot,'proofs':proofs,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
