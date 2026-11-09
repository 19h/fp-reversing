#!/usr/bin/env python3
"""Exact u32 operation partition under the captured private setup environment.
Opaque nonweak export addresses are nonzero, with no assigned native contents.
O(BV DAGs + solver resources) time/space; no native execution or IPC.
"""
import json
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from validate_daemon_record720_spill import parse_value
OP=z3.BitVec('core_dispatch_operation32',32)
def predicate(s,v):return z3.parse_smt2_string('(assert '+s+')',decls=v)[0]
def setup():
 d=json.loads((ROOT/'daemon_core_dispatch_symbolic.json').read_text());v={'core_dispatch_operation32':OP}
 for r in d['export_variables']:v[r['variable']]=z3.BitVec(r['variable'],64)
 env=z3.And(*[v[r['variable']]!=0 for r in d['export_variables']if not r['binding']['weak_import']]);p=[predicate(r['path_condition'],v)for r in d['paths']]
 return d,v,env,p
def sat(q):
 s=z3.Solver();s.set(timeout=30000);s.add(q);r=s.check();assert r!=z3.unknown,s.reason_unknown();return r==z3.sat
def bounds(q):
 lo=0;hi=0xffffffff
 while lo<hi:
  mid=(lo+hi)//2
  if sat(z3.And(q,z3.ULE(OP,mid))):hi=mid
  else:lo=mid+1
 smallest=lo;lo=0;hi=0xffffffff
 while lo<hi:
  mid=(lo+hi+1)//2
  if sat(z3.And(q,z3.UGE(OP,mid))):lo=mid
  else:hi=mid-1
 return smallest,lo
def obligations():
 d,v,env,p=setup();qs=[];routes=[];selected=[];defaults=[]
 for j,row in enumerate(d['paths']):
  b=row['boundary'];q=p[j];sample=int(row['operation_sample'],16)
  if b['pc']=='0x100528e20':defaults.append(j);continue
  if not sat(z3.And(env,q,OP!=sample)):lo=hi=sample
  else:lo,hi=bounds(z3.And(env,q))
  domain=OP==lo if lo==hi else z3.And(z3.UGE(OP,lo),z3.ULE(OP,hi))
  qs.append(('route_%02d_exact'%j,z3.And(env,z3.Xor(q,domain))));selected.append(domain)
  routes.append({'path_index':j,'operation_low_u32':hex(lo),'operation_high_u32':hex(hi),'cardinality':hi-lo+1,'boundary':b,'logical_edges':row['edges']})
 fallback=z3.Or(*[p[j]for j in defaults]);qs.append(('all_other_operations_default',z3.And(env,z3.Xor(fallback,z3.Not(z3.Or(*selected))))));qs.append(('all_u32_partition_complete',z3.And(env,z3.Not(z3.Or(*p)))));qs.append(('thirteen_paths_disjoint',z3.And(env,z3.Or(*[z3.And(p[j],p[k])for j in range(len(p))for k in range(j)]))))
 R=0x6800064000;F=0x680004f230;task=v['core_export_address_libSystem__mach_task_self_'];log=v['core_export_address_libSystem___os_log_default'];logfn=v['core_export_address_libSystem__os_log_type_enabled'];bad=[];taskbad=[];returnbad=[];logbad=[];fields=[]
 for j,row in enumerate(d['paths']):
  writes=[e for e in row['effects']if e['kind']=='write'];tw=[e for e in writes if e['address']==hex(F+0x348)];assert len(tw)==1
  taskbad.append(z3.And(p[j],parse_value(tw[0]['expression'],64,v)!=task));fields.append({'path_index':j,'mach_task_self_address_store':tw[0]})
  if j in defaults:
   w=[e for e in writes if e['address']==hex(R+24)];assert len(w)==1 and w[0]['size_bytes']==4 and w[0]['pc']=='0x100528ddc'
   bad.append(z3.And(p[j],parse_value(w[0]['expression'],32,v)!=0x74c29dee));returnbad.append(z3.And(p[j],parse_value(row['end_GPR_expressions']['sp'],64,v)!=0x6800060000))
  if row['boundary']['pc']in ['0x1005a8618','0x1005aaf60']:
   regs=row['end_GPR_expressions'];logbad.append(z3.And(p[j],z3.Or(parse_value(regs['x0'],64,v)!=log,parse_value(regs['x1'],64,v)!=0,parse_value(regs['x8'],64,v)!=logfn,parse_value(regs['x17'],64,v)!=0x5278)))
 qs.extend([('default_raw_record_result',z3.And(env,z3.Or(*bad))),('default_restores_entry_SP',z3.And(env,z3.Or(*returnbad))),('task_self_import_address_only',z3.And(env,z3.Or(*taskbad))),('logging_export_and_arguments',z3.And(env,z3.Or(*logbad)))])
 meta={'routes':routes,'default_path_indices':defaults,'default_cardinality':2**32-sum(r['cardinality']for r in routes),'total_u32_cardinality':2**32,'raw_result_write_PC':'0x100528ddc','raw_result_relative_offset_bytes':24,'raw_result_width_bytes':4,'raw_result_value':'0x74c29dee','native_status_meaning':'unknown','task_address_fields':fields,'common_nonweak_export_premise':env.sexpr(),'native_import_contents_assigned':False,'complete_native_route_or_transport_join':False}
 return qs,meta
def main():
 qs,meta=obligations();rows=[]
 for name,q in qs:
  original=ROOT/('daemon_core_dispatch_'+name+'_original.smt2');simple=ROOT/('daemon_core_dispatch_'+name+'.smt2');s=z3.Solver();s.add(q);original.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);simple.write_text(s.to_smt2());rows.append({'name':name,'original_file':original.name,'original_sha256':sha(original),'file':simple.name,'sha256':sha(simple),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_core_dispatch_symbolic.json','daemon_core_dispatch_symbolic.py','validate_daemon_record720_spill.py']},'proofs':rows,'metadata':meta,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_core_dispatch_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'routes':[{k:v for k,v in r.items()if k not in ['boundary','logical_edges']}for r in meta['routes']],'default_count':meta['default_cardinality']}),flush=True)
if __name__=='__main__':main()
