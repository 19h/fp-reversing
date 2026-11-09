#!/usr/bin/env python3
"""Fresh original-source continuous handovers and isolated record/consumer checks.
O(cases*visits + source/artifact bytes + solver resources) time; O(one CPU map,
journal + expression DAGs) space. No native API, hardware PAC, non-copy callee or IPC runs.
"""
import copy,json
from collections import Counter
import z3
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from capture_daemon_record720 import sha
from capture_daemon_mig_handover import capture
from daemon_mig_handover_symbolic import analyze,F,E,B
from prove_daemon_mig_handover import obligations,BIAS,R
from prove_daemon_operation_heads import variables,predicate
from validate_daemon_record720_spill import parse_value
from validate_daemon_core_dispatch import FreshReplay
from replay_daemon_descriptor_producers import IMPORTS

def continuous(case,variant):
 parent=json.loads((ROOT/'daemon_shared_roots_profiles.json').read_text())['cases'][0];src=json.loads((ROOT/'daemon_core_dispatch_source.json').read_text());dispatch=json.loads((ROOT/'daemon_core_dispatch_symbolic.json').read_text());path=dispatch['paths'][case['parent_path_index']];p=copy.deepcopy(parent);limit=src['operation_unread_prefix_source_visits'];op=int(case['operation32'],16);v=variables(case);replacements=[]
 data=bytearray((0 if variant==0 else 255 if variant==1 else(j*73+variant*19)&255)for j in range(72))
 if case['operation32']=='0xa70e6eb4':
  if case['path_class']=='allnonnull':
   for off in [0,56,64]:data[off:off+8]=(int.from_bytes(data[off:off+8],'little')or 1).to_bytes(8,'little')
  else:
   off=[0,56,64][variant%3];data[off:off+8]=bytes(8)
 if case['pointer_variable']:
  ptr=0 if case['path_class']=='null'else(1 if variant==0 else int.from_bytes(data[8:16],'little')or 1);data[8:16]=ptr.to_bytes(8,'little');replacements.append((v[case['pointer_variable']],z3.BitVecVal(ptr,64)))
 for r in case['borrowed_byte_variables']:replacements.append((v[r['variable']],z3.BitVecVal(data[r['relative_offset_bytes']],8)))
 globvalues={int(r['address'],16):(0 if variant==0 else(variant*61+int(r['address'],16)*17)&255)for r in case['unavailable_global_byte_variables']}
 for r in case['unavailable_global_byte_variables']:replacements.append((v[r['variable']],z3.BitVecVal(globvalues[int(r['address'],16)],8)))
 exports={r['symbol']:IMPORTS[r['symbol']]+variant*0x10000000 for r in dispatch['export_variables']+case['new_export_variables']}
 for r in dispatch['export_variables']+case['new_export_variables']:replacements.append((v[r['variable']],z3.BitVecVal(exports[r['symbol']],64)))
 replacements.append((v['core_dispatch_operation32'],z3.BitVecVal(op,32)))
 for name,x in v.items():
  if z3.is_bool(x):replacements.append((x,z3.BoolVal(False)))
 def ev(s,n):
  value=z3.simplify(z3.substitute(parse_value(s,n,v),*replacements));assert z3.is_bv_value(value),value;return value.as_long()
 p['initial_private_fixtures'].append({'address':hex(B),'bytes_hex':data.hex()})
 for a,b in globvalues.items():p['initial_image_fixtures'].append({'address':hex(a),'bytes_hex':bytes([b]).hex()})
 R=int(p['record_address'],16);K=(((R&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff;fixture=next(r for r in p['initial_private_fixtures']if r['address']==hex(R));raw=bytearray.fromhex(fixture['bytes_hex']);raw[12:16]=(op^K).to_bytes(4,'little');fixture['bytes_hex']=raw.hex();p['configuration']={**p['configuration'],'head_operation':hex(op),'input_variant':variant,'head_path_class':case['path_class']};p['source_visits']=p['source_visits'][:limit]
 for name in ['source_reads','source_writes','logical_edges']:p[name]=[e for e in p[name]if e['source_visit_index']<limit]
 for segment in [path,case]:
  effects=iter(segment['effects']);effect=next(effects,None);edges=iter(segment.get('edges',[]));edge=next(edges,None)
  for pc,rawhex in segment['steps']:
   j=len(p['source_visits']);p['source_visits'].append({'pc':hex(pc),'bytes_hex':rawhex,'image':'daemon'})
   while effect is not None and effect['pc']==hex(pc):
    e=effect;n=e['size_bytes'];row={'pc':hex(pc),'address':e['address'],'size_bytes':n,'source_visit_index':j};row['bytes_hex'if e['kind']=='read'else'after_hex']=ev(e['expression'],n*8).to_bytes(n,'little').hex();p['source_reads'if e['kind']=='read'else'source_writes'].append(row);effect=next(effects,None)
   if edge is not None and edge['pc']==hex(pc):p['logical_edges'].append({**edge,'source_visit_index':j});edge=next(edges,None)
  assert effect is None and edge is None
 regs=case['end_GPR_expressions'];p['boundary']={'pc':case['boundary']['pc'],'SP':hex(ev(regs['sp'],64)),'registers31':[hex(ev(regs['x'+str(j)],64))for j in range(31)]};s=z3.Solver();s.add(predicate(case['path_condition'],v));s.add(*[a==b for a,b in replacements]);assert s.check()==z3.sat
 replay=FreshReplay(p,variant%4,exports);result=replay.run();return {'operation32':hex(op),'path_class':case['path_class'],'input_variant':variant,'input_bytes_hex':data.hex(),'boundary':case['boundary']['pc'],'replay':result}

def execute(a,z,seeds,memory,pattern=0xc7):
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);u.mem_map(0x6800000000,0x100000);u.mem_write(0x6800000000,bytes([pattern])*0x100000)
 for pg in range(a&~4095,((z-1)&~4095)+4096,4096):u.mem_map(pg,4096);u.mem_write(pg,IMAGE.read(pg,4096))
 for name,val in seeds.items():u.reg_write(getattr(ar,'UC_ARM64_REG_'+name.upper()),val)
 u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000 if pattern&1 else 0x50000000)
 for at,n,value in memory:u.mem_write(at,(value&((1<<(8*n))-1)).to_bytes(n,'little'))
 u.emu_start(a,0,count=(z-a)//4);assert u.reg_read(ar.UC_ARM64_REG_PC)==z;return u

def local_cpu(meta):
 rows=[];mask=0xffffffff;decls={n:z3.BitVec(n,bits)for n,bits in [('handover_builder_SP64',64),('handover_borrowed_base64',64),('handover_computed_key32',32),('handover_phase27_32',32),('handover_phase20_32',32),('handover_input0_32',32),('handover_input4_32',32),('handover_input56_32',32),('handover_input48_64',64),('handover_input64_64',64)]}
 for j in range(8):
  S=F+j*256;Q=B+j*128;P=S+0x10cb8;key=(((P&mask)^0x7a9247f6)*0x31b6b333)&mask;d0=[0,mask,0x80000000,0x6cf4,1,0x7fffffff,0x5b,0x12345678][j];d4=(d0*73+19)&mask;d56=(~d0)&mask;phase27=[0x6cf4,0,mask,0x80000000,0x471c,1,0x4f79,0x1234][j];phase20=(d4^0x575d)&mask;q48=0x6800009000+j*8;q64=0xffffffffffffffff-j
  values=dict(zip(decls,[S,Q,key,phase27,phase20,d0,d4,d56,q48,q64],strict=True));replacement=[(decls[n],z3.BitVecVal(x,decls[n].size()))for n,x in values.items()]
  memory=[(S+0x990,8,Q+BIAS[0x10]),(S+0x978,8,Q+BIAS[0x70]),(S+0x980,8,Q+BIAS[0x28]),(S+0x9a0,8,q48),(S+0x998,8,Q+BIAS[0x68]),(S+0x988,8,Q+BIAS[0x50]),(S+0x9b8,8,q64),(S+0x9d0,4,d0)]
  u=execute(0x100466838,0x100466948,{'sp':S,'x27':phase27,'x20':phase20,'x28':d4,'x25':d56,'x26':Q+BIAS[0x78],'x24':Q+BIAS[0x60],'x19':Q+BIAS[0x40]},memory);written=set()
  for row in meta['record128_fields']:
   n=row['width_bytes'];expected=z3.simplify(z3.substitute(parse_value(row['expression'],8*n,decls),*replacement));assert z3.is_bv_value(expected);off=row['offset_bytes'];assert int.from_bytes(bytes(u.mem_read(P+off,n)),'little')==expected.as_long();written.update(range(off,off+n))
  assert len(written)==104 and all(bytes(u.mem_read(P+off,1))==bytes([0xc7])for off in range(136)if off not in written);rows.append({'component':'record128','case':j,'fields_checked':15,'defined_bytes':104,'A64_instructions':68})
  phase=(0x960f+j*0x8b3dc651)&mask;token=Q+24;u=execute(0x1004c45b8,0x1004c4600,{'sp':S,'x21':phase,'x19':token},[]);k40=(((P&mask)^0xc6d66014)*0x6b86592f)&mask;fields={0:(8,S+0xbfc0),16:(8,S+0x2cff),24:(4,(phase-k40-0xa5d)&mask),32:(8,token)};written=set()
  for off,(n,x)in fields.items():assert int.from_bytes(bytes(u.mem_read(P+off,n)),'little')==x;written.update(range(off,off+n))
  assert all(bytes(u.mem_read(P+off,1))==bytes([0xc7])for off in range(40)if off not in written);rows.append({'component':'record40','case':j,'fields_checked':4,'defined_bytes':28,'A64_instructions':18})
 for delta in [0,1,16,4096,(1<<64)-1,1<<63]:
  for status in [0,1,0xffffffff,0x80000000]:
   u=execute(0x100466a0c,0x100466a20,{'sp':F,'x19':F+0xb000,'x27':F+0x10000},[(F+0xba68,8,delta),(R+0x48,4,status)]);assert u.reg_read(ar.UC_ARM64_REG_SP)==(F+delta)&((1<<64)-1)and u.reg_read(ar.UC_ARM64_REG_X6)==status;rows.append({'component':'returned_word_status_consumer','delta':hex(delta),'status':hex(status),'A64_instructions':5})
 for flag in [0,1,0x80,0xff]:
  for result in [0,1,0x5a,0x5b,0x5c,0x80,0xff]:
   u=execute(0x1004c464c,0x1004c4674,{'sp':F,'x28':F+0x10000,'x21':0x960f},[(R+8,1,result),(F+0x2cff,1,flag)]);expected=0x960f^(0x12 if flag==0 or result==0x5b else 0);assert u.reg_read(ar.UC_ARM64_REG_X8)==expected;rows.append({'component':'two_byte_caller_gate','flag8':hex(flag),'result8':hex(result),'index':hex(expected),'A64_instructions':10})
 return rows

def main():
 source=json.loads((ROOT/'daemon_mig_handover_source.json').read_text());data=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());proofs=json.loads((ROOT/'daemon_mig_handover_proofs.json').read_text());assert capture()==source and analyze()==data;qs,counts,meta=obligations();assert meta==proofs['metadata']and counts==proofs['source_lift_counts']and len(qs)==len(proofs['proofs']);files=0
 for (name,q),r in zip(qs,proofs['proofs'],strict=True):
  assert name==r['name'];s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,(name,s.reason_unknown())
  for key,hashkey in [('file','sha256'),('original_file','original_sha256')]:
   p=ROOT/r[key];assert sha(p)==r[hashkey];s=z3.Solver();s.set(timeout=30000);s.add(z3.parse_smt2_file(str(p)));assert s.check()==z3.unsat,(name,key,s.reason_unknown());files+=1
  print(name,'rebuilt and read back',flush=True)
 parent=json.loads((ROOT/'daemon_operation_heads_symbolic.json').read_text());rows=[];totals=Counter()
 for stage in data['cases']:
  old=next(c for c in parent['cases']if c['operation32']==stage['operation32']and c['path_class']==stage['parent_head_class']);case={**old,**stage,'steps':old['steps']+stage['steps'],'effects':old['effects']+stage['effects'],'edges':stage['edges']}
  for variant in range(8):
   row=continuous(case,variant);rows.append(row);totals.update(row['replay']['verified_counts']);print(stage['operation32'],stage['path_class'],variant,'continuous CPU pass',flush=True)
 components=local_cpu(meta);kinds=Counter(r['component']for r in components);assert len(rows)==24 and len(components)==68
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_mig_handover_source.json','daemon_mig_handover_symbolic.json','daemon_mig_handover_proofs.json','capture_daemon_mig_handover.py','daemon_mig_handover_symbolic.py','prove_daemon_mig_handover.py','daemon_operation_heads_symbolic.json','daemon_shared_roots_profiles.json','validate_daemon_core_dispatch.py','replay_daemon_descriptor_producers.py']},'verified_counts':{'symbolic_cases':len(data['cases']),'source_obligations_rebuilt':len(qs),'accepted_SMT_files':files,'source_copy_calls':meta['total_source_copy_calls'],'continuous_A64_cases':len(rows),'isolated_component_cases':len(components),'isolated_component_A64_instructions':sum(r['A64_instructions']for r in components),'record128_defined_bytes':104,'record40_defined_bytes':28,'record128_undefined_bytes':24,'record40_undefined_bytes':12},'independent_A64_totals':dict(totals),'component_counts':dict(kinds),'fresh_replay_cases':rows,'isolated_component_cases':components,'symbolic_source_uses_Z3_scalar_semantics':True,'CPU_replay_uses_Unicorn':True,'native_target_executed':False,'host_API_executed':False,'idb_mutated':False,'new_port_emission_established':False,'native_callee_effects_executed':False,'cached_runtime_word_value_known':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_mig_handover_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'A64_totals':dict(totals),'components':dict(kinds),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()

