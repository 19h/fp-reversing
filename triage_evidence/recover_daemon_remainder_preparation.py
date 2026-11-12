#!/usr/bin/env python3
"""Composed remainder preparation, frame definition and nested helper entry.

O(snapshot+restored prefixes+cases*(visits+effects)) time/space;30 s/query.
An explicitly declared interior object word; no native API, IPC or PAC.
"""
import copy,json
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,TABLE,POOL,FIXUPS,selected
from daemon_callback_revisit_symbolic import ALLOWED_CALLS
from daemon_seed_material_symbolic import decode
from lskd_values_symbolic import mem,cell,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_frame_admission as Parent
R=Parent.Parent.Parent
P='daemon_remainder_preparation';ENTRY=0x1004c75a0;HELPER=0x1004234c4;STOP=0x10042379c
PINS={**Parent.PINS,'daemon_frame_admission_checks.json':'d590ccba476dd0fa42b5d9ef9968d310977821f7f02885e7bc82735a930fcc84',
 'daemon_frame_admission_audit.json':'e199f23f37dae1973a8f5c22f969c267668f1c8f08f115b262f38f9fe4bc3d84'}
DEPS=Parent.DEPS+['recover_daemon_frame_admission.py']
SPECS=[('preparation',0x10046a104,0x10046a230),('frame_writer',0x100530720,0x10053077c),
 ('nested_record_caller',0x10049d308,0x10049d430),('nested_helper_entry',HELPER,0x1004237a4)]

class Run(R.Run):
 def one(self,i):
  assert i.address!=STOP,'declared after nested-helper entry dispatch load'
  return super().one(i)

def inputs():
 pins,old=R.inputs()
 for n,d in PINS.items():assert sha(ROOT/n)==d,n
 return pins,old,json.loads(read(ROOT/'daemon_versioned_ingress_checks.json'))

def restore(snapshot,old,case):
 v=Run.from_snapshot(snapshot);R.R.H.advance(v,old['steps'][:case['prefix_source_visits']]);R.overlay(v,case['configuration']);rows=case['trace']['steps'];cut=next(j for j,r in enumerate(rows)if r['pc']==hex(ENTRY));cursor=0
 for model in case['API_models']:
  k=model['after_source_visits']
  if k>cut:break
  R.R.H.advance(v,rows[cursor:k]);cursor=k
  if model['name']=='malloc':
   a=int(case['configuration']['allocation'],16)
   for at in range(a,a+32):v.bytes.pop(at,None)
  for name,x in model['register_effects'].items():v.regs[v.key(name)]=decode(x,v.F)
 R.R.H.advance(v,rows[cursor:cut]);return v,cut

def source():
 out=[]
 for name,a,b in SPECS:
  raw=IMAGE.read(a,b-a);ii=list(Parent.DEC.disasm(raw,a));assert len(ii)*4==len(raw)
  out.append({'name':name,'start':hex(a),'end':hex(b),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 return out

def helper_key(r):return (resize(r,32)^0xb521e742)*0x74cae98d

def obligations():
 r,f,g,a,b,l,m=z3.BitVecs('preparation_record64 preparation_frame64 preparation_helper_frame64 preparation_a64 preparation_b64 preparation_l64 preparation_m64',64);op,t,phase=z3.BitVecs('preparation_operation32 preparation_tag32 preparation_phase32',32);qs=[]
 v=R.Algebra();v.seed('x29',r+0x98);v.run_block(0x10049d378,0x10049d3b4);k=helper_key(r)
 qs.append(('caller_key_matches_nested_family_for_all_u64_records',v.read('w12')!=k))
 v=R.Algebra();v.seed('x0',r);v.run_block(0x1004235bc,0x1004235f0)
 qs.append(('helper_decoder_key_matches_caller_for_all_records',v.read('w12')!=k))
 v=R.Algebra()
 for n,x in [('x29',r+0x98),('x8',l),('x11',a),('x10',b),('w9',op),('w12',k),('w19',phase)]:v.seed(n,x)
 v.run_block(0x10049d3b4,0x10049d3d8)
 qs.append(('nested_record_pointer_range_and_encoded_fields',z3.Or(cell(v,r,8)!=a,cell(v,r+8,8)!=l,cell(v,r+16,8)!=l,(cell(v,r+24,4)^k)!=op,cell(v,r+32,8)!=b,cell(v,r+40,4)-k!=phase-0x2d1a)))
 v=R.Algebra()
 for n,x in [('sp',g),('x0',r),('w12',k)]:v.seed(n,x)
 for at,n,x in [(r+40,4,t+k),(r+8,8,l),(r+16,8,m),(r+24,4,op^k)]:mem(v,at,n,x)
 v.run_block(0x1004235f0,0x10042365c)
 pred=z3.If(z3.Xor(z3.UGT(l,m),(t^0x49c5)&1!=0),z3.BitVecVal(1,32),z3.BitVecVal(0,32))
 qs.append(('helper_decodes_record_and_range_predicate',z3.Or(cell(v,g+0x20,8)!=r,cell(v,g+0x1c,4)!=op,cell(v,g,8)!=z3.ZeroExt(32,op+0x858da19d),v.read('w1')!=t,v.read('w13')!=t-0xb80,v.read('w12')!=pred)))
 v.run_block(0x10042365c,0x100423668);v.run_block(0x1004236a0,0x1004236a4)
 idx=t|(((t-0xb80)^0x19f0)*pred)
 qs.append(('helper_dispatch_index_projection',v.read('w15')!=idx))
 v=R.Algebra()
 for n,x in [('sp',g),('x0',r),('w12',k)]:v.seed(n,x)
 for at,n,x in [(r+40,4,0x2530+k),(r+8,8,l),(r+16,8,l),(r+24,4,op^k)]:mem(v,at,n,x)
 v.run_block(0x1004235f0,0x100423668);v.run_block(0x1004236a0,0x1004236a4)
 qs.append(('equal_range_tag2530_selects_index2570',v.read('w15')!=0x2570))
 v=R.Algebra();v.seed('sp',f)
 for j in [19,20,21,22,23,24,25,26,27,28,29,30]:v.seed('x'+str(j),z3.BitVec('helper_save_'+str(j),64))
 v.run_block(HELPER+4,0x1004234e8)
 qs.append(('helper_fixed_frame_geometry',z3.Or(v.read('sp')!=f-0x2f0,v.read('x29')!=f-16)))
 rows=[]
 for label,p in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(p);result=str(s.check());assert result=='unsat',(label,result);rows.append({'label':label,'query':s.to_smt2(),'result':result})
 return rows

def main():
 pins,old,parent=inputs();cases=[];totals=Counter()
 for original in parent['cases']:
  pc=original['configuration']
  if pc['kind']!='caller'or pc['name']not in ['prefix','extended']:continue
  base,cut=restore(pins['daemon_callback_revisit_snapshot.json'],old,original)
  for value in [0,1]:
   c={**pc,'parent_variant':pc['name'],'parent_entry_source_visits':cut,'parent_prefix_source_visits':original['prefix_source_visits'],
    'name':pc['name']+'_word'+str(value),'entry':hex(ENTRY),'declared_decoded_object_word':value,'prior_raw_object_word':'0x8b3dc64d','declared_raw_object_word':hex(value^Parent.C)}
   v=copy.copy(base);v.bytes=base.bytes.copy();v.regs=base.regs.copy();a=int(c['allocation'],16)+16;R.R.put(v,a,4,value^Parent.C)
   v.steps=[];v.pool={};v.cache={};v.fixups=set();v.zero_reads=[];v.changed=set();v.definitions=[];v.origins={};v.unknown_inputs_used={}
   initial={n:v.shape(x,16 if n.startswith('q')else 8)for n,x in v.regs.items()};flags=sum(1<<(31-j)for j,x in enumerate([v.n,v.z,v.carry,v.overflow])if z3.is_true(x))
   ALLOWED_CALLS.add(HELPER);boundary=v.run_revisit(ENTRY,limit=200000)
   assert boundary['kind']=='before_unresolved_source_effect'and not boundary['uncommitted_events']and int(boundary['pc'],16)==(STOP if value==0 else 0x10063736c),boundary
   assert not v.definitions
   counts={'source_visits':len(v.steps),'source_pool_entries':len(v.pool),'read_events':sum(e['kind']=='read'for r in v.steps for e in r['events']),'write_events':sum(e['kind']=='write'for r in v.steps for e in r['events'])};totals.update(counts)
   cases.append({'configuration':c,'trace':{'steps':v.steps,'boundary':boundary,'source_pool':v.pool,'used_fixups':list(map(hex,sorted(v.fixups))),'initial_registers':initial,'initial_NZCV':flags},'API_models':[],'counts':counts})
   print(json.dumps({'epoch':c['epoch'],'variant':c['name'],**counts}),flush=True)
 used={int(a,16)for c in cases for a in c['trace']['used_fixups']};collision=[{'slot':hex(a),'target':r['target'],'annotation':r['annotation']}for a,r in sorted(FIXUPS.items())if'div=0x9298 'in r['line']]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':R.R.H.THIN,'parent_pins':PINS,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source_regions':source(),'source_fixups':R.R.verify_fixups(used),'source_proofs':obligations(),
  'modifier9298_collision_slots':collision,'helper_dispatch_bank':selected(0x101031da0,0x100e99900,0x86,0x8c2,POOL),'cases':cases,'verified_counts':{'cases':len(cases),'epochs':2,'variants_per_epoch':4,**dict(totals)},
  'prefixes_reexecuted':False,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'actual_partial_fixture_resumed':False,'native_caller_admission_established':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)

if __name__=='__main__':main()
