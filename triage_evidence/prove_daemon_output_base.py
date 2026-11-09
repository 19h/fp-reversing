#!/usr/bin/env python3
"""All-u32 auxiliary partition, address key/decoder, shared byte packing and
all-u64 stack-epilogue obligations. Valid fixed cells and the retained mode/table
context are explicit premises. O(BV DAGs + solver resources) time/space.
No complete native call, outer-record epoch or Mach/IOKit join inferred.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE
from capture_daemon_record720 import sha
from daemon_output_base_dispatch import AUX,SPILLS,route_condition
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell
from validate_daemon_record720_spill import parse_value

def variables(d):
 v={'output_base_aux32':AUX}
 for name in d['component_context']['symbolic_GPRs'].values():v[name]=z3.BitVec(name,64)
 for group in ['borrowed_input_byte_variables','unavailable_frame_byte_variables']:
  for r in d[group]:v[r['variable']]=z3.BitVec(r['variable'],8)
 for n in ['N','Z','C','V']:v['output_base_entry_NZCV_'+n]=z3.Bool('output_base_entry_NZCV_'+n)
 return v

def predicate(text,v):return z3.parse_smt2_string('(assert '+text+')',decls=v)[0]

def obligations():
 d=json.loads((ROOT/'daemon_output_base_dispatch.json').read_text());b=json.loads((ROOT/'daemon_output_base_branches.json').read_text());v=variables(d);paths=[predicate(p['path_condition'],v)for p in d['paths']];qs=[];counts={};fallback=[]
 for tag,pc in SPILLS.items():
  selected=[paths[j]for j,p in enumerate(d['paths'])if p['boundary']['pc']==hex(pc)];assert len(selected)==1;qs.append(('interval_38acbb2a_7fffffff'if tag==0x7bed772d else'tag_%08x_exact'%tag,z3.Xor(selected[0],route_condition(tag))))
 fallback=[paths[j]for j,p in enumerate(d['paths'])if p['boundary']['pc']=='0x10095f074'];qs.append(('all_other_u32_tags_default',z3.Xor(z3.Or(*fallback),z3.Not(z3.Or(*[route_condition(t)for t in SPILLS])))));qs.append(('all_u32_partition_complete',z3.Not(z3.Or(*paths))));qs.append(('nine_paths_pairwise_disjoint',z3.Or(*[z3.And(paths[j],paths[k])for j in range(9)for k in range(j)])))
 qs.append(('default_raw_result_word',z3.Or(*[z3.And(paths[j],parse_value(p['end_GPR_expressions']['x23'],64,v)!=0x8b3dc651)for j,p in enumerate(d['paths'])if p['boundary']['pc']=='0x10095f074'])))
 def run(name,a,z,seeds=(),memory=()):
  m=LifetimeFlags({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for r,x in seeds:m.seed(r,x)
  for a,n,x in memory:mem(m,a,n,x)
  m.run(name);counts[name]=m.count;return m
 P=z3.BitVec('output_base_record_address64',64);m=run('record_key',0x100a59d18,0x100a59d68,[('x0',P)]);expected=(z3.Extract(31,0,P)^0xdc40790b)*0x5973a279;qs.append(('all_u64_outer_record_key',m.read('w11')!=expected))
 R=0x6800063f00;K,A=z3.BitVecs('output_base_key32 output_base_decoded_aux32',32);m=run('aux_decode',0x1006583b0,0x1006583dc,[('x0',R),('w11',K),('w15',0x471c)],[(R+20,4,A+K)]);qs.append(('all_u32_outer_aux_decode',m.read('w8')!=A))
 F=0x6800052060;words={o:z3.BitVec('output_base_saved_%x'%o,64)for o in range(0,96,8)};x=z3.BitVec('output_base_epilogue_X0',64);m=run('outer_epilogue',0x10095f090,0x10095f0b0,[('sp',F),('x0',x)],[(F+0xdef0+o,8,w)for o,w in words.items()]);mapping={'x28':0,'x27':8,'x26':16,'x25':24,'x24':32,'x23':40,'x22':48,'x21':56,'x20':64,'x19':72,'x29':80,'x30':88};qs.append(('all_u64_outer_epilogue',z3.Or(m.read('sp')!=F+0xdf50,m.read('x0')!=x,*[m.read(r)!=words[o]for r,o in mapping.items()])))
 packing=[];spills=[]
 for case in b['cases']:
  vs=variables(case);p=case['paths'][0];tag=int(case['continuation_tag'],16);writes=[e for e in p['effects']if e['kind']=='write'];word=next(e for e in writes if e['address']==hex(F+0x2a70)and e['size_bytes']==8);raw=parse_value(word['expression'],64,vs);data=z3.Concat(*[vs['output_base_input_byte_%d'%j]for j in range(8)]);packing.append(raw!=(data^0x9898989898989898^0xe3b88695c0d52dbc));out=next(e for e in writes if e['pc']==hex(SPILLS[tag]));spills.append(parse_value(out['expression'],64,vs)!=R)
 qs.append(('five_branches_all_input64_word',z3.Or(*packing)));qs.append(('five_branches_saved_caller_record',z3.Or(*spills)))
 return qs,counts,{'mode32':'0x471c','outer_epilogue_restore_map':mapping,'outer_frame_bytes':0xdf50,'native_epoch_join_established':False,'all_five_branch_input_bytes':8}
if __name__=='__main__':
 qs,counts,meta=obligations();rows=[]
 for name,q in qs:
  a=ROOT/f'daemon_output_base_{name}_original.smt2';f=ROOT/f'daemon_output_base_{name}.smt2';s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);f.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':f.name,'sha256':sha(f),'result':answer});print(name,answer,flush=True)
 r={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_output_base_dispatch.json','daemon_output_base_branches.json','daemon_output_base_dispatch.py','daemon_arena_lifetime_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'metadata':meta,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_output_base_proofs.json').write_text(json.dumps(r,indent=2)+'\n')
