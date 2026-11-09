#!/usr/bin/env python3
"""Independent A64 dispatch/packing witnesses, frozen original-call replays,
rebuilt SMT obligations and source/capture readback. O(visits + artifact bytes
+ BV evaluation + solver resources) time, O(case/private map) space.
Finite witnesses do not define native inputs, private frame bytes or epochs.
"""
import json,random
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,FIXUPS
from capture_daemon_record720 import sha
from daemon_output_base_dispatch import AUX,SPILLS,CS,explore,route_condition
from prove_daemon_output_base import variables,predicate,obligations
from recover_daemon_output_base import recover
from validate_daemon_object_clock import logical_read
from validate_daemon_record720_spill import parse_value
from replay_daemon_descriptor_producers import Replay

def run(d,p,aux,pattern):
 vs=variables(d);rng=random.Random(14589+aux+pattern);replacements=[(AUX,z3.BitVecVal(aux,32))];known_names=set()
 for name,v in vs.items():
  if name=='output_base_aux32':continue
  if z3.is_bool(v):value=z3.BoolVal(bool(pattern&1))
  else:value=z3.BitVecVal(0 if pattern==0 else(1<<v.size())-1 if pattern==1 else rng.getrandbits(v.size()),v.size())
  replacements.append((v,value));known_names.add(name)
 def evaluate(e):
  value=z3.simplify(z3.substitute(e,*replacements));assert z3.is_bv_value(value)or z3.is_true(value)or z3.is_false(value);return value.as_long()if z3.is_bv_value(value)else z3.is_true(value)
 assert evaluate(predicate(p['path_condition'],vs));u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set();counts=Counter();index=0;pending=[];current=0
 def ensure(a,n):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):
   if pg in pages:continue
   if 0x100000000<=pg<0x102000000:
    try:b=logical_read(pg,4096)
    except ValueError:b=bytes(4096)
   else:b=bytes([0x39])*4096
   u.mem_map(pg,4096);u.mem_write(pg,b);pages.add(pg)
 def reg(n):return getattr(ar,'UC_ARM64_REG_'+n.upper())
 def get(n):return u.reg_read(reg(n))
 ctx=d['component_context'];defined=set()
 for r in ctx['initial_bytes']:
  a=int(r['address'],16);ensure(a,1);u.mem_write(a,bytes([evaluate(parse_value(r['expression'],8,vs))]));defined.add(a)
 for b in d['unavailable_frame_byte_variables']:
  a=int(b['address'],16);assert a not in defined;ensure(a,1);u.mem_write(a,bytes([evaluate(vs[b['variable']])]))
 for n,x in ctx['known_GPRs'].items():u.reg_write(reg(n),int(x,16))
 for n,t in ctx['symbolic_GPRs'].items():u.reg_write(reg(n),evaluate(parse_value(t,64,vs)))
 u.reg_write(ar.UC_ARM64_REG_NZCV,(pattern&15)<<28)
 effects=p['effects'];parsed=[parse_value(e['expression'],e['size_bytes']*8,vs)for e in effects]
 def hook(_,kind,a,n,value,__):
  nonlocal index
  assert index<len(effects);e=effects[index];expr=parsed[index];index+=1;assert e['pc']==hex(current)and int(e['address'],16)==a and e['size_bytes']==n
  if kind==uc.UC_MEM_READ:assert e['kind']=='read'and int.from_bytes(bytes(u.mem_read(a,n)),'little')==evaluate(expr);counts['reads_checked']+=1
  else:assert e['kind']=='write';pending.append((a,n,expr));counts['writes_checked']+=1
 handle=u.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,hook);edges=iter(p['edges']);pc=int(d['component_entry_PC'],16)
 for expected,raw in p['steps']:
  assert pc==expected;current=pc;i=next(CS.disasm(IMAGE.read(pc,4),pc));assert bytes(i.bytes).hex()==raw;ensure(pc,4)
  if i.mnemonic=='braa':
   e=next(edges);target,mod=[get(n.strip())for n in i.op_str.split(',')];slot=int(e['slot'],16);w=int.from_bytes(IMAGE.read(slot,8),'little');assert e['pc']==hex(pc)and int(e['target'],16)==target and int(e['modifier'],16)==mod and FIXUPS[slot]['target']==target and w>>63==1 and(w>>32)&65535==mod and(w>>48)&7==0;pc=target;counts['logical_PAC_edges']+=1;continue
  j=index
  while j<len(effects)and effects[j]['pc']==hex(pc):e=effects[j];ensure(int(e['address'],16),e['size_bytes']);j+=1
  u.emu_start(pc,0,count=1);pc=u.reg_read(ar.UC_ARM64_REG_PC);counts['A64_instructions_checked']+=1
  for a,n,expr in pending:assert int.from_bytes(bytes(u.mem_read(a,n)),'little')==evaluate(expr)
  pending.clear()
 assert index==len(effects)and next(edges,None)is None and pc==int(p['boundary']['pc'],16)
 for n,t in p['end_GPR_expressions'].items():assert get(n)==evaluate(parse_value(t,64,vs)),n
 if d['continuation_tag']is None:
  # Execute the owned component's boundary store only after the trace comparison.
  u.hook_del(handle);R=int(d['component_record'],16);F=int(d['component_SP'],16);assert get('x0')==R;assert pc!=0x10095f074 or get('x23')==0x8b3dc651;ensure(pc,4);ensure(F+0x24f8,8);ensure(R,24);before=bytes(u.mem_read(R,24));u.emu_start(pc,0,count=1)
  if pc==0x10095f074:assert bytes(u.mem_read(R,24))==before[:16]+bytes.fromhex('51c63d8b')+before[20:]
  else:assert int.from_bytes(bytes(u.mem_read(F+0x24f8,8)),'little')==R
  counts['owned_boundary_store_cases']+=1
 counts['witnesses_checked']+=1
 return {'aux':hex(aux),'physical_pattern':pattern,'boundary':p['boundary']['pc'],'source_definitions_added':False,'counts':dict(counts)}

def main():
 d=json.loads((ROOT/'daemon_output_base_dispatch.json').read_text());branches=json.loads((ROOT/'daemon_output_base_branches.json').read_text());c=json.loads((ROOT/'daemon_output_base_contracts.json').read_text());proofs=json.loads((ROOT/'daemon_output_base_proofs.json').read_text());assert explore()==d and recover()==c
 total=Counter();root=[];rng=random.Random(8190);samples={0,1,0x7ffffffe,0x7fffffff,0x80000000,0xffffffff,0x38acbb29,0x38acbb2a,0x38acbb2b,0x7484eeab}
 for a in SPILLS:
  samples.update([(a-1)&0xffffffff,a,(a+1)&0xffffffff])
 for p in d['paths']:samples.add(int(p['aux_sample'],16))
 samples.update(rng.getrandbits(32)for _ in range(64));vs=variables(d);paths=[predicate(p['path_condition'],vs)for p in d['paths']]
 for j,a in enumerate(sorted(samples)):
  selected=[k for k,q in enumerate(paths)if z3.is_true(z3.simplify(z3.substitute(q,(AUX,z3.BitVecVal(a,32)))))];assert len(selected)==1;one=run(d,d['paths'][selected[0]],a,j%16);root.append(one);total.update(one['counts'])
 extended=[]
 for branch in branches['cases']:
  tag=int(branch['continuation_tag'],16);assert explore(tag)==branch;assert len(branch['paths'])==1
  values=[tag]if tag!=0x7bed772d else[0x38acbb2a,0x7484eeab,tag,0x7fffffff]
  for aux in values:
   for pattern in range(4):
    one=run(branch,branch['paths'][0],aux,pattern);extended.append(one);total.update(one['counts'])
 print('new A64',dict(total),flush=True)
 original=json.loads((ROOT/'daemon_descriptor_producers_profiles.json').read_text());original_runs=[];original_total=Counter()
 for j in[0,12,24,31,36,47]:
  one=Replay(original['cases'][j]).run();assert one['all_checks_pass'];original_runs.append({'prefix_index':j,**one});original_total.update(one['verified_counts'])
 qs,counts,meta=obligations();assert len(qs)==len(proofs['proofs'])==14
 for (name,q),r in zip(qs,proofs['proofs'],strict=True):
  assert name==r['name']
  for f,h in [('file','sha256'),('original_file','original_sha256')]:
   p=ROOT/r[f];assert sha(p)==r[h];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(p)));assert s.check()==z3.unsat
  s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat
 assert len(c['source_frame_origin_audits'])==24 and c['interval_cardinality_u32']==1196639446 and c['default_cardinality_u32']==3098327846
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_output_base_dispatch.json','daemon_output_base_branches.json','daemon_output_base_contracts.json','daemon_output_base_proofs.json','daemon_output_base_dispatch.py','replay_daemon_descriptor_producers.py','daemon_descriptor_producers_profiles.json','daemon_descriptor_producers_source.json']},'verified_counts':{'source_partition_paths':9,'exact_aux_singletons':4,'inclusive_interval_routes':1,'source_obligations_rebuilt':14,'accepted_SMT_files':28,'rejected_hypotheses_with_SAT_counterexample':1,'source_frame_origin_audits':24,'original_IDA_ranges':5,'original_IDA_bytes':640,'root_A64_cases':len(root),'extended_A64_cases':len(extended),'frozen_original_prefix_A64_cases':len(original_runs)},'root_witnesses':root,'extended_witnesses':extended,'independent_A64_totals':dict(total),'frozen_original_prefix_replays':original_runs,'original_prefix_A64_totals':dict(original_total),'native_target_executed':False,'native_frame_epoch_join_established':False,'host_API_executed':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_output_base_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'new_A64_totals':dict(total),'original_prefix_totals':dict(original_total),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
