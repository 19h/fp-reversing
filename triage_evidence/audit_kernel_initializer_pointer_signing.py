#!/usr/bin/env python3
"""Opaque-PAC source proofs, all-image custody, finite CPU cases and controls.
Worst-case quadratic child-command rescans plus linear records/journals/RAM;
SMT search separate, 30 s/query. No native signing or callback invocation.
"""
import json
from collections import Counter
from hashlib import sha256
import z3
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_timeout_execution import Model as Parent
from audit_kernel_mapping_context import DEC
from lskd_values_symbolic import resize
import recover_kernel_initializer_pointer_signing as R
import probe_kernel_initializer_pointer_signing as CPU
from replay_kernel_initializer_pointer_signing import oracle,Replay
STRIP=z3.Function('IPS_strip_instruction_pointer64',z3.BitVecSort(64),z3.BitVecSort(64))
SIGNIA=z3.Function('IPS_sign_instruction_pointer_IA64',z3.BitVecSort(64),z3.BitVecSort(64),z3.BitVecSort(64))
SIGNDA=z3.Function('IPS_sign_data_pointer_DA64',z3.BitVecSort(64),z3.BitVecSort(64),z3.BitVecSort(64))
class Model(Parent):
 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic in ['xpaci','pacia1716','pacda']:
    if self.next is not None:self.edge_checks.append(self.next==i.address)
    self.next=resize(i.address+4,64);self.pc=i.address;self.visited.add(i.address);self.count+=1
    if i.mnemonic=='xpaci':assert i.op_str=='x16';self.write('x16',STRIP(self.read('x16')))
    elif i.mnemonic=='pacia1716':self.write('x17',SIGNIA(self.read('x17'),self.read('x16')))
    else:assert i.op_str=='x16, x17';self.write('x16',SIGNDA(self.read('x16'),self.read('x17')))
    continue
   old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=old_e,old_c
  return self
def source_proofs(e):
 proofs=[];coverage=[];base=0x6700000000
 def fresh():v=Model(e);v.regions=[(base,1024)];return v
 def cut(v,a,b):
  f=next(f for f in e['functions']+e['fairplay_callback_bodies'] if int(f['start'],16)<=a<b<=int(f['end'],16));offset=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[offset:offset+b-a].hex()}]};return v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV','PAC_semantics':'Uninterpreted strip, IA-sign and DA-sign functions; signature values and keys unknown.'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instructions':v.count,'linked_edges':len(v.edge_checks)});print('proved',label,flush=True)
 flags=z3.BitVec('IPS_flags8',8);v=fresh();v.seed('x12',base);v.setmem(base+64,1,flags);cut(v,0xfffffe000c656d00,0xfffffe000c656d10);prove('only_section_low_byte9_or10_is_admitted',v,v.next!=z3.If(z3.Or(flags==9,flags==10),resize(0xfffffe000c656d10,64),resize(0xfffffe000c656cd8,64)))
 pointer,size,index,array=z3.BitVecs('IPS_pointer64 IPS_size64 IPS_index64 IPS_array64',64)
 v=fresh();v.seed('x12',base);v.setmem(base+32,8,pointer);cut(v,0xfffffe000c656d10,0xfffffe000c656d18);prove('null_section_address_is_skipped',v,v.next!=z3.If(pointer==0,resize(0xfffffe000c656cd8,64),resize(0xfffffe000c656d18,64)))
 v=fresh();v.seed('x12',base);v.setmem(base+40,8,size);cut(v,0xfffffe000c656d18,0xfffffe000c656d24);prove('fewer_than8_bytes_is_skipped',v,v.next!=z3.If(z3.ULT(size,8),resize(0xfffffe000c656cd8,64),resize(0xfffffe000c656d24,64)))
 v=fresh();v.seed('x15',size);cut(v,0xfffffe000c656d24,0xfffffe000c656d34);prove('at_least8_complete_pointers_selects_unrolled_loop',v,z3.Or(v.read('x16')!=z3.LShR(size,3),v.next!=z3.If(z3.UGE(z3.LShR(size,3),8),resize(0xfffffe000c656da0,64),resize(0xfffffe000c656d34,64))),[z3.UGE(size,8)])
 v=fresh();v.seed('x15',size);cut(v,0xfffffe000c656d38,0xfffffe000c656d40);tail=z3.LShR(size,3)&7;prove('scalar_tail_count_uses_complete_pointer_count_mod8',v,z3.Or(v.read('x15')!=tail,v.next!=z3.If(tail!=0,resize(0xfffffe000c656d50,64),resize(0xfffffe000c656d40,64))))
 v=fresh();v.seed('x14',index);v.seed('x13',array);cut(v,0xfffffe000c656d50,0xfffffe000c656d68);offset=index<<3;signed=z3.SignExt(32,z3.Extract(31,0,offset));poison=((array+offset)&0xffffffffffff)|(0x2bad<<48);prove('scalar_slot_uses_signed32_offset_or2bad_poison',v,v.read('x1')!=z3.If(offset==signed,array+signed,poison))
 for j,a in enumerate([0xfffffe000c656d78,0xfffffe000c656de0,0xfffffe000c656e30,0xfffffe000c656e80,0xfffffe000c656ed0,0xfffffe000c656f20,0xfffffe000c656f70,0xfffffe000c656fc0,0xfffffe000c657010]):
  v=fresh();v.setmem(v.sp0+8,8,pointer);v.seed('x1' if j==0 else 'x2',base+512);cut(v,a,a+36);expected=SIGNIA(STRIP(pointer),resize(0x4a27,64));prove('nonzero_pointer_tail_'+str(j)+'_stores_IA_sign_strip_with_modifier4a27',v,z3.Or(v.load(base+512,8)!=expected,v.read('x16')!=expected,v.read('x17')!=expected),[pointer!=0])
 for j,c in enumerate(e['fairplay_class_initializers']):
  a=int(c['initializer'],16);p=c['superclass_pointer'];slot=int(p['slot'],16);parent=int(p['target'],16);v=fresh();v.regions.append((slot,8));v.setmem(slot,8,parent);cut(v,a,a+48);prove('FairPlay_initializer'+str(j)+'_forwards_exact_metaclass_name_superclass_size_to_constructor_stub',v,z3.Or(v.next!=int(c['constructor_stub'],16),v.read('x0')!=int(c['metaclass'],16),v.read('x1')!=int(c['class_name_address'],16),v.read('x2')!=parent,v.read('x3')!=c['class_size_bytes'],v.read('x30')!=a+48))
  v=fresh();dest=base+768;v.seed('x0',dest);cut(v,a+48,a+76);modifier=(dest&0xffffffffffff)|(0xcda1<<48);prove('FairPlay_initializer'+str(j)+'_stores_DA_signed_metaclass_vtable_with_address_modifier_cda1',v,v.load(dest,8)!=SIGNDA(resize(int(c['metaclass_vtable_address_point'],16),64),resize(modifier,64)))
 return proofs,coverage
def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();im=Image();proofs,coverage=source_proofs(e);components=[];totals=Counter()
 for c in CPU.configurations():
  row=CPU.Probe(im,e,c).run();row['independent_oracle']=oracle(im,row);row['independent_replay']=Replay(im,row).run();totals.update(row['independent_replay']);components.append(row);print('case',c['label'],len(row['source_visits']),flush=True)
 original=components[0];sequence=original['independent_oracle']['expected_pointer_sequence'];expected=[p for t in e['pointer_tables'] for p in t['pointers'] if int(p['target'],16)];assert sequence==[{'slot':p['slot'],'value':p['target'],'segment':t['segment_command'],'section_index':t['section_index']} for t in e['pointer_tables'] for p in t['pointers'] if int(p['target'],16)];assert len(expected)==6362 and original['independent_oracle']['eligible_sections']==674
 assert all(any(int(f['start'],16)<=int(v['PC'],16)<int(f['end'],16) for f in e['functions']) for row in components for v in row['source_visits'])
 fairplay=[t for t in e['pointer_tables'] if t['image']=='com.apple.driver.FairPlayIOKit'];custody=[]
 for t in fairplay:
  for p in t['pointers']:
   ordinal=next(j for j,r in enumerate(sequence) if r['slot']==p['slot']);custody.append({'section':t['section'],'pointer':p,'ordered_nonzero_store_ordinal':ordinal,'target_symbols':e['fairplay_target_symbols'][p['target']]})
 controls=[]
 for label,index,pc in [('scalar_pointer_store',4,0xfffffe000c656d98),('unrolled_pointer_store',8,0xfffffe000c656e00),('walker_segment_call',22,0xfffffe000c47cd24)]:
  c=CPU.configurations()[index];row=CPU.Probe(im,e,c,pc).run();positive=components[index];keys=['configuration','initial_registers31','initial_SP','initial_NZCV','initial_private_sha256'];assert all(row[k]==positive[k] for k in keys)
  try:oracle(im,row)
  except AssertionError as error:rejection=list(error.args[0])
  else:raise AssertionError(('changed_source_accepted',label,c['label']))
  controls.append({'label':label,'configuration':c,'source_word_mutated_to_NOP':hex(pc),'all_initial_fields_match':True,'oracle_rejection':rejection,'journal_sha256':sha256(json.dumps({k:row[k] for k in ['source_visits','source_reads','source_writes','logical_PAC_envelopes']},sort_keys=True,separators=(',',':')).encode()).hexdigest(),'control_journal_rebuilt_by_delivery_verifier':True});print('rejected',label,flush=True)
 stats={'components':len(components),'source_visits':sum(len(r['source_visits']) for r in components),'source_queries_unsat':len(proofs),'proof_instruction_instances':sum(q['instructions'] for q in coverage),'proof_distinct_PCs':len({pc for q in coverage for pc in q['PCs']}),'semantic_assertions':sum(len(r['independent_oracle']['checks']) for r in components),'original_collection_segment_calls':len(original['signer_entries']),'original_collection_pointer_stores':len(sequence),'fairplay_pointer_stores':len(custody),'changed_source_controls':len(controls),'module_callback_invocations':0,'native_target_executions':0,'continuous_startup_visits_added':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_initializer_pointer_signing.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_proofs':proofs,'proof_coverage':coverage,'components':components,'fairplay_pointer_custody':custody,'negative_controls':controls,'independent_totals':stats,'independent_replay_totals':dict(totals),'prior_continuous_startup_unchanged':True,'native_target_executed':False,'hardware_PAC_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
