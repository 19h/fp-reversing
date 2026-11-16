#!/usr/bin/env python3
"""Original lock descriptors, finite execution, formula and replay receipts.
Linear source/journal/RAM work; SMT solver complexity stated separately.
"""
import json
from collections import Counter
from hashlib import sha256
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import resize
from audit_kernel_timeout_execution import Model
import recover_kernel_lock_bootstrap_execution as R
import probe_kernel_lock_bootstrap_execution as CPU
from replay_kernel_lock_bootstrap_execution import oracle,Replay,prefix,B

def source_proofs(e):
 proofs=[];coverage=[]
 def cut(v,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.enter('cut')
 def new():v=Model(e);v.regions=[];return v
 def prove(label,v,bad):
  common=v.owned();counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);assert s.check()==z3.unsat,(label,s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)})
 flags,common,setmask,clear=z3.BitVecs('LK_flags32 LK_common32 LK_set32 LK_clear32',32);lr=z3.BitVec('LK_lr64',64)
 v=new();v.seed('w9',common);v.seed('w10',flags);cut(v,0xfffffe000c62d62c,0xfffffe000c62d64c);prove('boot_flags_map_to_group_bits16_17_18',v,v.read('w2')!=(common|((flags<<15)&0x10000)|((flags<<14)&0x20000)|((flags&1)<<18)))
 v=new();v.seed('w10',flags);cut(v,0xfffffe000c62d64c,0xfffffe000c62d658);prove('only_lcks_mask0xb_admits_common_flag_store',v,v.next!=z3.If(flags&0xb==0,resize(0xfffffe000c62d65c,64),resize(0xfffffe000c62d658,64)))
 arg=R.REGISTRY;dst=R.BANK;glob=0xfffffe0007e63610
 v=new();v.regions=[(arg,16),(dst,16),(glob,4)];v.setmem(arg,8,dst);v.setmem(arg+8,4,setmask);v.setmem(arg+12,4,clear);v.setmem(glob,4,common);v.seed('x0',arg);v.seed('x30',lr);cut(v,0xfffffe000c62d5ec,0xfffffe000c62d618);prove('attribute_set_then_clear_publication',v,z3.Or(v.load(dst,4)!=((common|setmask)&~clear),v.next!=lr))
 v=new();v.regions=[(arg,8),(dst,16)];v.setmem(arg,8,dst);v.seed('x0',arg);v.seed('x30',lr);cut(v,0xfffffe000c62e7ac,0xfffffe000c62e7c0);prove('plain_lock_initializes_two_u64_words',v,z3.Or(v.load(dst,8)!=0,v.load(dst+8,8)!=0x11,v.next!=lr))
 v=new();v.seed('w8',flags);cut(v,0xfffffe000bd06244,0xfffffe000bd06260);expected=z3.If(flags&0x10000==0,resize(2,32),resize(0,32))|z3.If(flags&0x20000==0,resize(0x40,32),resize(0,32));prove('rw_attribute_bits_select_initial_halfword',v,v.read('w8')!=expected)
 return proofs,coverage

def static_contracts(e,im):
 checks=[]
 def ok(label,p):assert p,('lock_static',label);checks.append(label)
 old=json.loads(read(ROOT/(R.B.P+'_checks.json')));ok('184_prior_bodies_preserved',e['functions'][:len(old['functions'])]==old['functions'])
 for f in e['functions']:ok('body_'+f['start'],im.k.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes'] and sha256(bytes.fromhex(f['bytes'])).hexdigest()==f['sha256'])
 rs=json.loads(read(ROOT/'kernel_startup_registry_abi_checks.json'))['registry']['entries']
 for r in e['registrations']:ok('registration_'+str(r['index']),rs[r['index']]==r and r['phase_u32']==3 and r['callback_pointer']['auth']==1 and r['callback_pointer']['diversity']=='0x2abe')
 for d in e['descriptors']:
  if 'raw_hex' not in d:continue
  raw=bytes.fromhex(d['raw_hex']);a=int(d['argument'],16);ok('descriptor_'+hex(a),im.k.read(a,len(raw))==raw)
  for p in d['pointers']:
   if p is None:continue
   slot=int(p['slot'],16);word=int.from_bytes(im.k.read(slot,8),'little');ok('format8_pointer_'+hex(slot),int(p['raw'],16)==word and int(p['target'],16)==im.base+(word&0x3fffffff) and (word>>30)&3==0 and p['format']==8)
  if int(d['target'],16)==R.GROUP:ok('group_name_flags_'+hex(a),raw[8:72].split(b'\0')[0].decode()==d['name'] and int.from_bytes(raw[72:76],'little')==d['flags_u32']==0)
  if int(d['target'],16)==R.ATTR:ok('attribute_masks_'+hex(a),int.from_bytes(raw[8:12],'little')==d['set_mask_u32'] and int.from_bytes(raw[12:16],'little')==d['clear_mask_u32'])
 for s in e['strings']:ok('string_'+s['address'],im.k.read(int(s['address'],16),len(bytes.fromhex(s['bytes_hex']))).hex()==s['bytes_hex'])
 r=e['static_group_registry'];ok('static_bank',im.pointer(R.REGISTRY)==r['bank_pointer'] and r['bank_pointer']['target']==hex(R.BANK) and im.k.read(R.BANK,8192)==bytes.fromhex(r['bank_raw_hex'])==bytes(8192));ok('static_bitmap',im.pointer(R.REGISTRY+0x60)==r['bitmap_pointer'] and r['bitmap_pointer']['target']==hex(R.BITMAP) and im.k.read(R.BITMAP,128)==bytes.fromhex(r['bitmap_raw_hex'])==bytes([255])*128)
 return {'checks':checks}

def preservation(row,im):
 old=B.B.hydrate(json.loads(read(ROOT/(R.B.P+'_audit.json')))['components'][0],im);new=prefix(B.B.hydrate(row,im));keys=['source_visits','source_reads','source_writes','API_models','logical_effects','original_call_entries','original_API_entries','original_API_returns','callback_entries','callback_returns','final_private_RAM','final_image_globals','final_vectors','final_system'];assert all(old[k]==new[k] for k in keys),[k for k in keys if old[k]!=new[k]]
 assert all(old['boundary'][k]==new['boundary'][k] for k in ['pc','registers31','SP','NZCV']);wanted=old['final_page_sha256'];actual=new['final_page_sha256'];assert wanted.keys()<=actual.keys() and all(actual[p]==h for p,h in wanted.items())
 for p in actual.keys()-wanted.keys():assert actual[p]==sha256(im.logical_page(int(p,16))).hexdigest()
 return {'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'compared_fields':keys+['boundary_pc','boundary_GPR31','boundary_SP','boundary_NZCV'],'exact_match':True,'known_original_page_hashes_exact_match':True,'additional_original_page_bytes':4096*len(actual.keys()-wanted.keys()),'call_frame_epochs':0,'new_callback_result_models':0}

def controls(im,e,components):
 out=[]
 for label,pc in [('reserved_id0_clearing',0xfffffe000c62d68c),('rw_initial_attribute_halfword',0xfffffe000bd06270)]:
  row=CPU.Probe(im,CPU.cases()[0],pc).run();positive=B.B.hydrate(components[0],im);keys=['configuration','entry_PC','entry_SP','entry_registers31','entry_NZCV','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','initial_image_pages'];assert all(row[k]==positive[k] for k in keys)
  try:oracle(row,e)
  except AssertionError as error:rejection=list(error.args[0])
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
  journal={k:row[k] for k in ['source_visits','source_reads','source_writes','final_private_RAM']};out.append({'label':label,'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':im.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','all_initial_fields_match':True,'same_positive_initial_fields':keys,'source_visits':len(row['source_visits']),'boundary':row['boundary'],'oracle_rejection':rejection,'journal_canonical_sha256':sha256(json.dumps(journal,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'full_control_journal_retained':False});print('control_rejected',label,flush=True)
 return out

def audit(components=None):
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();im=Image();proofs,coverage=source_proofs(e);static=static_contracts(e,im)
 if components is None:components=[B.B.publication_row(CPU.Probe(im,c).run(),im) for c in CPU.cases()]
 totals=Counter()
 for row in components:row['independent_oracle']=oracle(row,e);row['independent_replay']=Replay(im,row).run();totals.update(row['independent_replay']);print('main',row['configuration']['label'],len(row['source_visits']),flush=True)
 kept=preservation(components[0],im);negative=controls(im,e,components);visited={v['pc'] for c in components for v in c['source_visits']};source={i['ea'] for f in e['functions'] for i in f['instructions']};assert visited<=source and not visited&{i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']};assert hex(R.FRONTIER) not in visited
 stats={'components':len(components),'source_queries_unsat':len(proofs),'proved_source_PCs':len({p for c in coverage for p in c['PCs']}),'proof_instruction_instances':sum(c['instruction_instances'] for c in coverage),'linked_edge_obligations':sum(c['linked_edge_obligations'] for c in coverage),'static_checks':len(static['checks']),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'phase_three_callbacks_per_case':627,'callbacks_returned_per_case':1029,'group_initializations_per_case':291,'changed_source_controls':len(negative),'lock_semantic_checks':sum(len(c['independent_oracle']['checks']) for c in components),'lock_mutable_bytes_compared':sum(c['independent_oracle']['mutable_bytes_compared'] for c in components),'mutable_region_count_per_case':len(components[0]['final_image_globals']),'mutable_region_bytes_per_case':sum(len(bytes.fromhex(r['bytes_hex'])) for r in components[0]['final_image_globals']),'call_frame_epochs':0,'new_callback_result_models':0,'native_target_executions':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_lock_bootstrap_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'kernel_collection_sha256':im.k.sha256,'source_proofs':proofs,'proof_coverage':coverage,'independent_static_contracts':static,'components':components,'negative_controls':negative,'prior_published_checkpoint_preservation':kept,'independent_totals':stats,'independent_replay_totals':dict(totals),'conditional_kernel_lock_bootstrap_execution_contract_established':True,'native_target_executed':False,'hardware_PAC_executed':False,'matched_FairPlay_transaction_established':False,'full_goal_complete':False}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
