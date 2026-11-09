#!/usr/bin/env python3
"""Original kmsg constructor policy, cache/zero-check and real send integration.
O(image+visits+RAM+effects), O(image+RAM+journals); fixed-width scalar proofs.
Declared raw storage/zone epochs do not prove runtime cache or OOM behavior.
"""
import json,struct
from collections import Counter
from z3 import BitVec,BitVecVal,ZeroExt,Extract,LShR,And,ULE,ULT,UGE,If,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_rpc502_vm_handoff import decode
from replay_kernel_send_right_lifecycle import Replay as ProducerReplay
from replay_kernel_kmsg_allocation import Replay
P='kernel_kmsg_allocation';R=0x6500000000;SIZE=0x100000;KMSG=R+0xd0000;HEAPH=R+0xd4000;HEAPB=R+0xd8000;ZONE=R+0xb0000;STATS=R+0xb1000;CACHE=R+0xb2000;SLOTS=R+0xb3000;SPARE=R+0xb3100;PENDING=R+0xb4000;THREAD=R+0x2c000;U=(1<<32)-1
def val(b,o,n=4):return int.from_bytes(b[o:o+n],'little')
def constructor_plan(s,a,d,f):
 extra=0
 if not f&1:
  if 4*d>U-8:return None
  extra=4*d+8
 base=s+68+extra;total=base+a
 if s+68>U or base>U or total>U:return None
 h=b=cls=0
 if total>=193:
  assert not f&4
  if f&16:assert a==0;h=base;cls=2
  else:
   if 16*d>U-36:return None
   prefix=d*(16 if f&1 else 12)
   if prefix>U-32:return None
   prefix+=32
   if total<prefix:return None
   h=16*d+36;b=total-prefix;cls=3 if h>=169 else 1
 heapflags=((f&8)<<12)|(((f>>1)&1)<<2)
 return{'class':cls,'header':h,'body':b,'heapflags':heapflags,'aux':a&0xffff,'state_byte':int(bool(f&32))}
def fields(p):
 b=bytearray(256);b[0x3f]=p['class']<<6;struct.pack_into('<H',b,0x30,p['aux']);b[0x32]=p['state_byte']
 if p['class']:
  struct.pack_into('<QQII',b,0xe8,KMSG+0x40 if p['class']==1 else HEAPH,HEAPB if p['body']else 0,p['header'],p['body'])
 return bytes(b)
def fixture_plan(c):
 cpu=c.get('cpu_index',0);mode=c.get('cache_mode','primary');cache_at=CACHE+(cpu<<14);stats_at=STATS+(cpu<<14);p=[(KMSG,bytes(256)),(KMSG+256,b'\xa5')]
 if 'dirty_offset'in c:p.append((KMSG+c['dirty_offset'],b'\xaa'))
 z=bytearray(256);struct.pack_into('<H',z,0x34,256);struct.pack_into('<Q',z,0x40,0 if mode=='null_pointer'else CACHE);cb=bytearray(64);struct.pack_into('<HHQQ',cb,4,int(mode=='primary'),int(mode=='swap'),SLOTS,SPARE);pending=bytearray(80);pending[0x4c]=c.get('pending_flag',0)
 p.extend([(ZONE,bytes(z)),(stats_at,bytes(16)),(cache_at,bytes(cb)),(SLOTS,struct.pack('<QQ',KMSG if mode=='primary'else 0,0)),(SPARE,struct.pack('<QQ',KMSG if mode=='swap'else 0,0)),(PENDING,bytes(pending)),(THREAD+0x1b8,struct.pack('<H',cpu)),(THREAD+0x1c0,struct.pack('<Q',PENDING)),(THREAD+0x1c8,bytes(4))])
 if c['phase']=='allocator':p.extend([(HEAPH,b'\xa5'*4096),(HEAPB,b'\xa5'*4096)])
 return p
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());producer=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];old=json.loads((ROOT/'kernel_notification_send_profiles.json').read_text())['cases'];counts=Counter();totals=Counter();summaries=[];proofs=[]
 for o,s in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/s)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h
  assert all(o[k]is False for k in FLAGS)
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==13 and sum(len(f['instructions'])for f in src['functions'])==2071
 for f in src['functions']:
  a=int(f['start'],16);raw=im.k.read(a,int(f['end'],16)-a);assert raw.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==f['instructions']
 for e in src['allocation_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 cell=src['original_kmsg_zone_cells'];assert cell['bytes16_hex']==im.k.read(int(cell['address'],16),16).hex()=='00'*16
 rec=src['candidate_kmsg_initialization_record'];assert im.pointer(int(rec['name_pointer']['slot'],16))==rec['name_pointer']and im.k.read(int(rec['address'],16),48).hex()==rec['bytes48_hex']and im.k.read(int(rec['name_address'],16),10).hex()==rec['name_bytes_hex']and rec['adjacent_size_word_u64']==256 and rec['startup_consumer_and_runtime_zone_identity_established']is False;counts['original_file_zero_cells_and_candidate_record_recaptured']=1
 s=BitVec('send_size32',32);d=BitVec('descriptor_count32',32);f=BitVec('flags32',32);wide=ZeroExt(32,s)+68;h=ZeroExt(32,d)*16+36
 qs=[('inline_flags1_aux0_all_u32',And(ULE(wide,U),ULT(wide,193)),ULE(s,124),None),('external_descriptor_header_choice_admitted_u32',If(UGE(h,169),3,1),If(UGE(d,9),3,1),ULE(h,U)),('raw_heap_flag_mapping_all_u32',((f&8)<<12)|((LShR(f,1)&1)<<2),(ZeroExt(31,Extract(3,3,f))<<15)|(ZeroExt(31,Extract(1,1,f))<<2),None)]
 for name,left,right,domain in qs:
  solver=Solver()
  if domain is not None:solver.add(domain)
  solver.add(left!=right);assert solver.check()==unsat;proofs.append({'name':name,'domain':None if domain is None else str(domain),'query':solver.sexpr(),'result':'unsat'});counts['bounded_scalar_policy_proofs_unsat']+=1
 fresh_producer=ProducerReplay(im,producer).run();rows=prof['cases'];assert len(rows)==36
 for j,r in enumerate(rows):
  c=r['configuration'];notif=c['phase']=='notification';eff={'size':44,'aux':0,'descriptors':0,'flags':1}if notif else c;plan=constructor_plan(eff['size'],eff.get('aux',0),eff.get('descriptors',0),eff.get('flags',1));mode=c.get('cache_mode','primary');dirty='dirty_offset'in c;heapfail=c.get('heap_failure');popped=plan is not None and not heapfail and mode not in['empty','null_pointer'];returned=r['boundary']['kind']in['allocator_returned','outer_notification_caller_returned'];cpu=c.get('cpu_index',0);cache_at=CACHE+(cpu<<14);stats_at=STATS+(cpu<<14)
  assert all(r[k]is False for k in FLAGS)and r['raw_kmsg_guard_hex']=='a5'and r['selected_cache_address']==hex(cache_at)and r['selected_statistics_address']==hex(stats_at)
  base=decode(producer['final_private_RAM'])if notif else bytes(SIZE);assert decode(r['initial_state_transfer'])==base and r['initial_state_transfer']['path']==('kernel_send_right_lifecycle_profiles.json'if notif else'private_zero_RAM');counts['exact_declared_source_or_zero_RAM_origin_checked']+=1
  init=bytearray(base);prefix=[]
  if notif:
   prefix=[(R+0xdc000,b'\xa5'*4),(THREAD+0xc8,bytes(2)),(R+0xc0048,struct.pack('<Q',R+0xdd000))]
   assert len(r['memory_overlays'])==3
   for (a,b),e in zip(prefix,r['memory_overlays'],strict=True):assert e['address']==hex(a)and e['before_hex']==init[a-R:a-R+len(b)].hex()and e['after_hex']==b.hex();init[a-R:a-R+len(b)]=b
   regs=list(producer['boundary']['registers31']);regs[4]=hex(R+0xdc000 if c.get('accepted_output')else 0);assert r['entry_registers31']==regs and r['entry_SP']==producer['boundary']['SP']and r['entry_NZCV']==producer['boundary']['NZCV']and r['entry_Q_registers32']==producer['final_Q_registers32'];counts['notification_actual_CPU_entry_with_explicit_output_variant_checked']+=1
  else:
   regs=['0x0']*31
   for k,x in enumerate([c['size'],c.get('aux',0),c.get('descriptors',0),c.get('flags',1)]):regs[k]=hex(x)
   regs[30]=hex(R+0xe0000);assert r['entry_registers31']==regs and r['entry_SP']==hex(R+0xf0000)
  environment=fixture_plan(c);assert len(environment)==len(r['allocation_environment_overlays'])and r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in prefix+environment]
  for (a,b),e in zip(environment,r['allocation_environment_overlays'],strict=True):assert e['address']==hex(a)and e['before_hex']==init[a-R:a-R+len(b)].hex()and e['after_hex']==b.hex();init[a-R:a-R+len(b)]=b;counts['explicit_allocation_environment_patches_checked']+=1
  initialglobals=r['initial_image_fixtures'];zoneglobal={'address':'0xfffffe000caec680','bytes_hex':struct.pack('<QQ',ZONE,STATS).hex()};assert[{k:e[k]for k in['address','bytes_hex']}for e in initialglobals[-1:]]==[zoneglobal]
  if notif:
   inherited=producer['final_image_globals'];assert[{k:e[k]for k in['address','bytes_hex']}for e in initialglobals[:len(inherited)]]==inherited and[(e['address'],e['bytes_hex'])for e in initialglobals[len(inherited):-1]]==[('0xfffffe0007e62b68',struct.pack('<Q',R+0xdc800).hex()),('0xfffffe0007e5c221','00')]
  else:assert len(initialglobals)==1
  counts['declared_zone_and_other_image_global_epochs_checked']+=1
  models=r['API_models'];by={}
  for m in models:by.setdefault(m['symbol'],[]).append(m)
  assert'declared_kmsg_allocate'not in by and not any('zone_allocate'in name or'zero_check'in name for name in by);counts['no_whole_kmsg_zone_or_zero_check_model_checked']+=1
  frames=r['allocation_frames'];entry=next(e for e in frames if e['pc']=='0xfffffe000bcc24a4');assert entry['arguments4']==[hex(x)for x in[eff['size'],eff.get('aux',0),eff.get('descriptors',0),eff.get('flags',1)]]
  zoneframes=[e for e in frames if e['pc']=='0xfffffe000bd75c64'];zero=[e for e in frames if e['pc']=='0xfffffe000bc9d9c0'];zeroret=[e for e in frames if e['pc']=='0xfffffe000bd75d20'];stats=bytes.fromhex(r['final_statistics16_hex']);cache=bytes.fromhex(r['final_cache64_hex']);raw=bytes.fromhex(r['final_raw_kmsg256_hex'])
  assert bool(zoneframes)==(plan is not None and not heapfail)
  if zoneframes:assert len(zoneframes)==1 and zoneframes[0]['arguments4'][:3]==[hex(ZONE),hex(STATS),'0x8004']and zoneframes[0]['thread_nesting']==0;counts['original_zone_request_flags_and_entry_context_checked']+=1
  if popped:
   assert len(zero)==len(zeroret)==1 and zero[0]['arguments4'][:2]==[hex(KMSG),'0x100']and zeroret[0]['arguments4'][0]==hex(int(dirty))and val(stats,0,8)==256 and stats[8:]==bytes(8)and r['final_thread_nesting']==0
   wantcache=bytearray(init[cache_at-R:cache_at-R+64]);struct.pack_into('<HH',wantcache,4,0,0)
   if mode=='swap':struct.pack_into('<QQ',wantcache,8,SPARE,SLOTS)
   assert cache==bytes(wantcache)and r['final_slots16_hex']==r['final_spare_slots16_hex']=='00'*16;counts['original_cache_pop_statistics_and_thread_unwind_checked']+=1
   covered=set()
   for e in r['source_reads']:
    a=int(e['address'],16)
    if 0xfffffe000bc9d9c0<=int(e['pc'],16)<0xfffffe000bc9daa0 and KMSG<=a<KMSG+256:assert a+e['size_bytes']<=KMSG+256;covered.update(range(a,a+e['size_bytes']))
   assert covered==set(range(KMSG,KMSG+256));counts['original_zero_check_complete_256byte_read_coverage_checked']+=1
  else:assert not zero and val(stats,0,8)==0
  if mode in['empty','null_pointer']:
   assert r['boundary']['kind']==('before_original_cache_refill'if mode=='empty'else'before_original_zone_fallback')and r['final_thread_nesting']==1 and not returned;counts['held_context_refill_or_fallback_frontiers_checked']+=1
  elif dirty:
   want=bytearray(256);want[c['dirty_offset']]=0xaa;assert raw==bytes(want)and r['boundary']['kind']=='before_original_zero_check_failure'and r['boundary']['registers31'][:3]==[hex(ZONE),hex(KMSG),'0x100'];counts['original_dirty_cache_zero_guard_frontiers_checked']+=1
  elif not notif:
   assert returned and r['boundary']['kind']=='allocator_returned'and r['boundary']['registers31'][18:]==r['entry_registers31'][18:]and r['boundary']['SP']==r['entry_SP']
   if plan is None or heapfail:assert r['boundary']['registers31'][0]=='0x0'and raw==bytes(256)and not zoneframes;counts['original_arithmetic_or_checked_heap_NULL_returns_checked']+=1
   else:assert r['boundary']['registers31'][0]==hex(KMSG)and raw==fields(plan);counts['original_constructed_field_images_checked']+=1
  if not popped and mode not in['empty','null_pointer']:assert r['final_thread_nesting']==0
  expectedheaps=[]
  if plan is not None:
   if plan['body']:expectedheaps.append(('body',0xfffffe0007f8bfb0,plan['body'],plan['heapflags'],0 if heapfail=='body'else HEAPB))
   if plan['class']in[2,3]and heapfail!='body':expectedheaps.append(('header',0xfffffe0007f8db59 if plan['class']==3 else 0xfffffe0007f8e1e9,plan['header'],plan['heapflags'],0 if heapfail=='header'else HEAPH))
  gotheaps=[m for m in models if m['symbol'].startswith('declared_raw_')]
  assert[(m['symbol'],[int(x,16)for x in m['arguments8'][:4]],int(m['return_value'],16))for m in gotheaps]==[('declared_raw_'+kind+'_heap_allocation',[heap,size,flags,0],result)for kind,heap,size,flags,result in expectedheaps];counts['original_external_heap_allocation_plan_checked']+=1
  cleanup=by.get('declared_failed_header_body_release_request',[]);assert len(cleanup)==int(heapfail=='header')
  if cleanup:assert cleanup[0]['arguments8'][:3]==['0xfffffe0007f8bfb0',hex(HEAPB),hex(plan['body'])];counts['original_header_failure_body_release_request_checked']+=1
  pending=by.get('declared_pending_preemption_helper',[]);assert len(pending)==int(c.get('pending_flag',0)==4)
  if pending:assert pending[0]['arguments8'][:3]==[hex(ZONE),hex(STATS),'0x8004'];counts['original_post_unwind_pending_helper_ABI_checked']+=1
  if notif:
   q=c['queue_status'];prior=next(o for o in old if o['configuration'].get('storage_class')==0 and o['configuration'].get('queue_status',0)==q and not any(o['configuration'].get(k)for k in['allocation_null','destination_null','destination_inactive','thread_flags','send_bytes','preflight_status']))
   assert raw==bytes.fromhex(prior['final_kmsg1024_hex'])[:256]and r['final_header32_hex']==prior['final_header32_hex']and r['final_body12_hex']==prior['final_body12_hex']and r['final_trailer68_hex']==prior['final_trailer68_hex']and r['boundary']['kind']=='outer_notification_caller_returned'and r['final_source_port144_hex']==producer['final_ports144_hex'][hex(R+0x83000)];counts['actual_constructor_to_original_notification_payload_and_return_join_checked']+=1
   assert raw[0x3f]>>6==0 and r['final_accepted_u32']==(1 if c.get('accepted_output')else 0xa5a5a5a5);counts['actual_44byte_inline_constructor_policy_checked']+=1
   queued=by['declared_queue_send'];assert len(queued)==1 and queued[0]['arguments8'][:4]==[hex(R+0xc0028),hex(KMSG),'0x50001','0x0']and int(queued[0]['return_value'],16)==q
   helper=next(e for e in r['entry_frames']if e['pc']=='0xfffffe000bcd059c');assert int(helper['arguments5'][0],16)==(0 if q==0x10000003 else q)
   destruction=by.get('declared_message_destroy',[]);assert[m['arguments8'][:2]for m in destruction]==([]if q==0 else[[hex(KMSG),'0x1'if q==0x10000003 else'0x0']]);counts['allocator_integrated_queue_status_helper_return_and_destroy_oracles_checked']+=1
  for k,m in enumerate(models):
   assert m['native_effects_executed']is False;want=[hex(((i+1)*0x123456789abcdef)^((k+1)*0x8b3dc651))for i in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0);counts['declared_primitive_clobber_models_checked']+=1
  for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_dynamic_original_instruction_recaptured']+=1
  totals.update(Replay(im,r).run());summaries.append({'case':j,'phase':c['phase'],'plan':plan,'visits':len(r['source_visits']),'boundary':r['boundary']['kind']});print(json.dumps({**summaries[-1],'fresh_replay':'pass'}),flush=True)
 counts.update(cases=36,functions=13,captured_instructions=2071)
 deps=[P+'_source.json',P+'_profiles.json','kernel_notification_send_profiles.json','kernel_send_right_lifecycle_profiles.json','replay_'+P+'.py','replay_kernel_notification_send.py','replay_kernel_send_right_lifecycle.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_rpc502_vm_handoff.py','recover_kernel_send_right_lifecycle.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_notification_producer_replay':fresh_producer,'proofs':proofs,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
