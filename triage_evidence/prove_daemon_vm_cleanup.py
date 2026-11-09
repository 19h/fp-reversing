#!/usr/bin/env python3
"""Original local BV/byte-array ABI and dispatch equations, plus fixed-context
daemon cleanup continuation quantified over its VM return and NZCV bits.
Source-consistent first-read cuts pin all other continuation memory; they
are not a universal environment or native VM/free/IPC claim.
O(source + BV/array DAGs + solver resources) time and space.
"""
import json
from collections import defaultdict
import z3
from daemon_receive_tools import ROOT,IMAGE
from daemon_output_base_dispatch import CS
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell,resize
from capture_daemon_record720 import sha
class Local(LifetimeFlags):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);original=self.c
  for ins in CS.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if ins.mnemonic=='adds':
    assert ins.address==0xfffffe000bdc1ecc and ins.op_str=='x8, x1, x2';a,b=self.read('x1'),self.read('x2');wide=z3.ZeroExt(1,a)+z3.ZeroExt(1,b);r=z3.Extract(63,0,wide);self.write('x8',r);self.negative=z3.Extract(63,63,r)==1;self.equal=r==0;self.carry=z3.Extract(64,64,wide)==1;self.overflow=z3.And(z3.Extract(63,63,a)==z3.Extract(63,63,b),z3.Extract(63,63,a)!=z3.Extract(63,63,r));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};super().run('one')
  self.c=original
def obligations():
 c=json.loads((ROOT/'daemon_vm_cleanup_contracts.json').read_text());cache=c['cache'];kf=c['kernel']['functions'][0];qs=[];counts={};domains=[]
 def raw(a,n):
  for f in cache['functions']+c['kernel']['functions']:
   s=int(f['start'],16);b=bytes.fromhex(f['bytes'])
   if s<=a and a+n<=s+len(b):return b[a-s:a-s+n]
  return IMAGE.read(a,n)
 def run(name,a,z,seeds=(),memory=(),cls=Local):
  m=cls({'spans':[{'label':name,'start':hex(a),'bytes_hex':raw(a,z-a).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('vmclean_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 STATUS=z3.BitVec('vmclean_trap_status32',32);m=run('cache_fallback',0x1805497e0,0x1805497ec,[('w0',STATUS)]);qs.append(('all_fast_trap_statuses',m.condition('eq')!=(STATUS==0x10000003)))
 TASK,ADDRESS,SIZE=z3.BitVecs('vmclean_task_input64 vmclean_address64 vmclean_size64',64);m=run('logger_arguments',0x18054982c,0x180549844,[('x21',TASK),('x20',ADDRESS),('x19',SIZE)]);qs.append(('all_logger_argument_words',z3.Or(m.read('x0')!=0x20,m.read('x1')!=z3.ZeroExt(32,z3.Extract(31,0,TASK)),m.read('x2')!=ADDRESS,m.read('x3')!=SIZE,m.read('x4')!=0,m.read('x5')!=0)))
 class Bytes(LifetimeFlags):
  def __init__(self,c):
   super().__init__(c);self.array=z3.Array('vmclean_initial_memory',z3.BitVecSort(64),z3.BitVecSort(8))
   for at,value in [(0x1eb065de0,0x100000000),(0x18057d628,0x3000001513),(0x18057d758,0x12c100000000)]:self.store(z3.BitVecVal(at,64),8,z3.BitVecVal(value,64),0)
  def load(self,a,n):return z3.Concat(*[z3.Select(self.array,resize(a,64)+k)for k in reversed(range(n))])if n>1 else z3.Select(self.array,resize(a,64))
  def store(self,a,n,v,pc):
   a=resize(a,64);v=resize(v,8*n)
   for k in range(n):self.array=z3.Store(self.array,a+k,z3.Extract(8*k+7,8*k,v))
 REPLY=z3.BitVec('vmclean_reply_name32',32);S=0x600000efb0
 a=run('request_body',0x18056f11c,0x18056f12c,[('sp',S),('x1',ADDRESS),('x2',SIZE)],cls=Bytes);a.seed('x0',z3.ZeroExt(32,REPLY));a.seed('x19',TASK);a.c={'spans':[{'label':'head','start':hex(0x18056f130),'bytes_hex':raw(0x18056f130,0x44).hex()}]};a.run('head');counts['request_total_source_lifts']=a.count
 fields=[(0,4,z3.BitVecVal(0x1513,32)),(4,4,z3.BitVecVal(48,32)),(8,4,z3.Extract(31,0,TASK)),(12,4,REPLY),(16,4,z3.BitVecVal(0,32)),(20,4,z3.BitVecVal(4801,32)),(24,8,z3.BitVecVal(0x100000000,64)),(32,8,ADDRESS),(40,8,SIZE)];bad=[a.load(z3.BitVecVal(S+off,64),n)!=value for off,n,value in fields];bad+=[a.read('x0')!=S,a.read('x1')!=0x200000003,a.read('x2')!=0x3000001513,a.read('x3')!=z3.Concat(REPLY,z3.Extract(31,0,TASK)),a.read('x4')!=0x12c100000000,a.read('x5')!=z3.Concat(REPLY,z3.BitVecVal(0,32)),a.read('x6')!=44,a.read('x7')!=0];qs.append(('all_MIG_request_field_bits',z3.Or(*bad)))
 m=run('send_result_cleanup_gate',0x18056f17c,0x18056f1a0,[('w0',STATUS)]);qs.append(('all_message_return_cleanup_classes',m.condition('ne')!=z3.Or(STATUS==0x10000002,STATUS==0x10000003,STATUS==0x10000010)))
 MID=z3.BitVec('vmclean_reply_id32',32);m=run('reply_special_id',0x18056f1a8,0x18056f1b0,[('sp',S)],[(S+20,4,MID)]);n=run('reply_expected_id',0x18056f1b4,0x18056f1bc,[('w8',m.read('w8'))]);qs.append(('all_reply_id_words',z3.Or(m.condition('eq')!=(MID==0x47),n.condition('eq')!=(MID==4901))))
 ARG=0x70000;NAME=z3.BitVec('vmclean_kernel_task_name32',32);m=run('kernel_name_argument',0xfffffe000bcdb4fc,0xfffffe000bcdb508,[('x0',ARG)],[(ARG,4,NAME)]);n=run('kernel_range_arguments',0xfffffe000bcdb544,0xfffffe000bcdb548,[('x19',ARG)],[(ARG+8,8,ADDRESS),(ARG+16,8,SIZE)]);e=run('kernel_rejected_lookup',0xfffffe000bcdb52c,0xfffffe000bcdb534);qs.append(('all_kernel_argument_words_and_lookup_error',z3.Or(m.read('x0')!=z3.ZeroExt(32,NAME),m.read('x1')!=0,n.read('x1')!=ADDRESS,n.read('x2')!=SIZE,e.read('w0')!=0x10000003)))
 PAGE=z3.BitVec('vmclean_kernel_page_shift_byte8',8);add=run('kernel_range_sum',0xfffffe000bdc1ecc,0xfffffe000bdc1ed0,[('x1',ADDRESS),('x2',SIZE)]);SUM=ADDRESS+SIZE;m=run('kernel_aligned_endpoints',0xfffffe000bdc1ed4,0xfffffe000bdc1ef8,[('x0',0x80000),('x1',ADDRESS),('x8',SUM)],[(0x8002c,1,PAGE)]);MASK32=~(z3.BitVecVal(0xffffffff,32)<<(z3.ZeroExt(24,PAGE)&31));MASK=z3.ZeroExt(32,MASK32);START=ADDRESS&~MASK;END=(SUM+MASK)&~MASK;args=run('kernel_tail_options',0xfffffe000bdc1efc,0xfffffe000bdc1f04);zero=run('kernel_zero_size',0xfffffe000bdc1f10,0xfffffe000bdc1f14);invalid=run('kernel_invalid',0xfffffe000bdc1f08,0xfffffe000bdc1f0c);qs.append(('all_kernel_address_size_and_page_shift_bits',z3.Or(add.read('x8')!=SUM,add.condition('hs')!=z3.ULT(SUM,ADDRESS),m.read('x1')!=START,m.read('x2')!=END,m.condition('ls')!=z3.ULE(END,START),args.read('x3')!=0,args.read('x4')!=0,zero.read('w0')!=0,invalid.read('w0')!=4)))
 profiles=json.loads((ROOT/'daemon_vm_cleanup_profiles.json').read_text())['cases'];selected=[p for p in profiles if p['configuration']['client_bit_plan']=='neither'and p['configuration']['VM_cleanup_return_model']=='0x0']
 for profile in selected:
  tag=profile['configuration']['query_result_model']+'_'+str(profile['source_index']);event=next(e for e in profile['API_model_events']if e['pc']=='0x1004776c0');cut=event['source_visit_index'];steps=[e for e in profile['source_visits']if e['source_visit_index']>cut];reads=defaultdict(list);writes=defaultdict(list)
  for e in profile['source_reads']:reads[e['source_visit_index']].append(e)
  for e in profile['source_writes']:writes[e['source_visit_index']].append(e)
  data={};cuts={};bad=[]
  class Trace(LifetimeFlags):
   def load(self,at,n):
    at=z3.simplify(at);assert z3.is_bv_value(at),('symbolic address',tag,at);a=at.as_long();assert all(a+k in data for k in range(n)),(tag,hex(a),n);return z3.Concat(*[data[a+k]for k in reversed(range(n))])if n>1 else data[a]
   def store(self,at,n,value,pc):
    at=z3.simplify(at);assert z3.is_bv_value(at);a=at.as_long();value=resize(value,8*n)
    for k in range(n):data[a+k]=z3.Extract(8*k+7,8*k,value)
  t=Trace({'spans':[]})
  for j,v in enumerate(event['after_registers31']):t.seed('x'+str(j),int(v,16))
  t.seed('x0',z3.BitVec('vmclean_daemon_return_'+tag,64));t.seed('sp',int(event['SP'],16));t.negative,t.equal,t.carry,t.overflow=[z3.Bool('vmclean_return_'+tag+'_'+f)for f in ['N','Z','C','V']];edges={e['source_visit_index']:e for e in profile['logical_edges']}
  for row in steps:
   seq=row['source_visit_index'];pc=int(row['pc'],16);ins=next(CS.disasm(IMAGE.read(pc,4),pc))
   for e in reads[seq]:
    a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex'])
    for k,v in enumerate(b):
     if a+k not in data:data[a+k]=z3.BitVecVal(v,8);cuts[hex(a+k)]=v
    bad.append(t.load(z3.BitVecVal(a,64),len(b))!=z3.BitVecVal(int.from_bytes(b,'little'),8*len(b)))
   if ins.mnemonic in ['braa','br']:
    edge=edges[seq];reg=ins.op_str.split(',')[0].strip();bad.append(t.read(reg)!=int(edge['target'],16));continue
   assert ins.mnemonic not in ['b','bl','svc','ret','retab','retaa'],(tag,hex(pc),ins.mnemonic)
   t.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':row['bytes_hex']}]};t.run('one')
   for e in writes[seq]:bad.append(t.load(z3.BitVecVal(int(e['address'],16),64),e['size_bytes'])!=z3.BitVecVal(int.from_bytes(bytes.fromhex(e['after_hex']),'little'),8*e['size_bytes']))
  bad.append(t.read('x0')!=0x6800030000);qs.append(('all_VM_return_and_NZCV_bits_'+tag,z3.Or(*bad)));counts['daemon_suffix_'+tag]=len(steps);domains.append({'name':tag,'initial_VM_return_bits':64,'initial_NZCV_bits':4,'all_other_registers':'retained API-return context','source_visits':len(steps),'first_read_cut_bytes':cuts,'final_free_argument':'0x6800030000','native_feasibility_established':False})
 return qs,counts,domains
if __name__=='__main__':
 qs,counts,domains=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('daemon_vm_cleanup_'+name+'_original.smt2');b=ROOT/('daemon_vm_cleanup_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer,s.model()if answer=='sat'else s.reason_unknown());b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_vm_cleanup_contracts.json','daemon_vm_cleanup_profiles.json','daemon_arena_lifetime_symbolic.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'daemon_proof_domains':domains,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_vm_cleanup_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
