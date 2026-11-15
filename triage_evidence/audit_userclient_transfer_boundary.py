#!/usr/bin/env python3
"""Source-level adapter ABI and lifecycle obligations, with opaque external calls.
O(I+query DAG) construction/space; SMT cost separate, 30 s/query.
Authenticated dispatch, stable objects/packets and ordinary returns are premises.
"""
import copy
import json
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM,ARM64_OP_REG
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_transfer_boundary as R

DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True
MASK=(1<<64)-1
def bv(x,n=64):
 if isinstance(x,int):return z3.BitVecVal(x%(1<<n),n)
 return x if x.size()==n else z3.Extract(n-1,0,x) if x.size()>n else z3.ZeroExt(n-x.size(),x)
def same(xs,ys):return z3.Or(*[a!=b for a,b in zip(xs,ys)]) if len(xs)==len(ys) else z3.BoolVal(True)

class Model:
 def __init__(self,e,kind,case='normal',output_alias=False):
  self.kind,self.case,self.output_alias=kind,case,output_alias;self.e=e
  self.reg={f'x{j}':z3.BitVec(f'TB_initial_X{j}',64) for j in range(31)};self.initial=dict(self.reg)
  names='sp user packet output provider address extent state task descriptor buffer staging vtask vbuffer vprovider kernel_task page_global kernel_global core_return provider_return'
  for name in names.split():setattr(self,name,z3.BitVec('TB_'+name+'64',64))
  self.extent_parameter=self.extent;self.extent=bv(self.extent_parameter,32);self.shift=z3.BitVec('TB_page_shift32',32)
  self.kernel_global=bv(int(next(r['target'] for r in e['bindings'] if r['role']=='kernel_task'),16))
  self.page_global=bv(int(next(r['target'] for r in e['bindings'] if r['role']=='page_shift'),16))
  self.count_in,self.count_out=z3.BitVecs('TB_count_in64 TB_count_out64',64)
  self.prepare_task,self.prepare_buffer=z3.BitVecs('TB_task_prepare32 TB_buffer_prepare32',32)
  self.reg['sp']=self.sp;self.private={};self.stores=[];self.events=[];self.guards=[];self.checks=[];self.visited=[];self.auth=[];self.call_number=0
  if kind=='handler':self.seed('x0',self.user);self.seed('x1',self.packet);self.seed('x2',self.packet if output_alias else self.output)
  else:
   for r,v in [('x0',self.provider),('x1',self.address),('x2',self.extent_parameter),('x3',self.state),('x4',self.task)]:self.seed(r,v)
  f=e['functions'][kind];self.start=int(f['start'],16);self.end=int(f['end'],16)
  self.ins={i.address:i for i in DEC.disasm(bytes.fromhex(f['bytes_hex']),self.start)}
 def seed(self,r,v):self.reg[r]=bv(v);return self
 def width(self,r):return 32 if r.startswith('w') else 64
 def regread(self,r):
  r={'fp':'x29','lr':'x30'}.get(r,r)
  return bv(0,self.width(r)) if r in ['xzr','wzr'] else bv(self.reg['x'+r[1:] if r.startswith('w') else r],self.width(r))
 def regwrite(self,r,v):
  r={'fp':'x29','lr':'x30'}.get(r,r)
  if r not in ['xzr','wzr']:self.reg['x'+r[1:] if r.startswith('w') else r]=bv(bv(v,self.width(r)))
 def op(self,i,o,n):
  v=bv(o.imm,n) if o.type==ARM64_OP_IMM else bv(self.regread(i.reg_name(o.reg)),n)
  return v<<o.shift.value if o.shift.value else v
 def address_of(self,i,o):return z3.simplify(self.regread(i.reg_name(o.mem.base))+o.mem.disp)
 def key(self,a,n):return z3.simplify(a).sexpr(),n
 def load(self,a,n,part=0):
  pc=self.pc
  # Each abstract external load carries a separate source-address obligation.
  d={0xfffffe000a504058:(self.packet,self.address),0xfffffe000a50405c:(self.packet+8,self.extent),
   0xfffffe000a504060:(self.user+0xe0+8*part,self.task if part==0 else self.state),
   0xfffffe000a504064:(self.user+0xd8,self.provider),0xfffffe000a504068:(self.provider,self.vprovider),
   0xfffffe000a504080:(self.vprovider+0xa20,z3.BitVec('TB_provider_function64',64)),
   0xfffffe000a5040ac:(self.packet,self.address),0xfffffe000a5040b4:(self.packet+8,self.extent)}
  for p,receiver,table in [(0x51e0,self.descriptor,self.vtask),(0x525c,self.buffer,self.vbuffer),
   (0x52a0,self.buffer,self.vbuffer),(0x52c4,self.descriptor,self.vtask),(0x5308,self.descriptor,self.vtask),
   (0x534c,self.buffer,self.vbuffer),(0x5384,self.buffer,self.vbuffer),(0x539c,self.descriptor,self.vtask),(0x53c0,self.descriptor,self.vtask)]:d[0xfffffe000a500000+p]=(receiver,table)
  for p,table,off in [(0x5200,self.vtask,0x218),(0x527c,self.vbuffer,0x218),(0x52b0,self.vbuffer,0x308),
   (0x52d4,self.vtask,0x208),(0x5328,self.vtask,0x210),(0x536c,self.vbuffer,0x220),
   (0x538c,self.vbuffer,0x28),(0x53ac,self.vtask,0x220),(0x53c8,self.vtask,0x28)]:d[0xfffffe000a500000+p]=(table+off,z3.BitVec(f'TB_virtual_{p:x}_64',64))
  d.update({0xfffffe000a505228:(bv(0xfffffe000847c608),self.kernel_global),
   0xfffffe000a50522c:(self.kernel_global,self.kernel_task),0xfffffe000a505234:(bv(0xfffffe000847c5b0),self.page_global),
   0xfffffe000a505238:(self.page_global,self.shift)})
  if pc in d:
   expected,value=d[pc];self.checks.append(a==expected);return bv(value,n*8)
  return self.private[self.key(a,n)]
 def store(self,a,n,v):
  self.private[self.key(a,n)]=bv(v,n*8);self.stores.append((self.pc,a,n,bv(v,n*8)))
 def call(self):
  role=R.CALLS[self.pc][0];args=[self.regread('x'+str(j)) for j in range(5)]
  self.events.append((role,args,self.pc));self.call_number+=1
  results={'task_descriptor':bv(0) if self.case=='task_null' else self.descriptor,
   'task_prepare':bv(self.prepare_task),'buffer_descriptor':bv(0) if self.case=='buffer_null' else self.buffer,
   'buffer_prepare':bv(self.prepare_buffer),'buffer_address':self.staging,'copy_in':self.count_in,
   'core':self.core_return,'copy_out':self.count_out,'provider':self.provider_return}
  for j in [*range(19),30]:self.reg['x'+str(j)]=z3.BitVec(f'TB_call{self.call_number}_X{j}',64)
  if role in results:self.regwrite('x0',results[role])
 def run(self):
  pc=self.start
  while True:
   assert pc in self.ins and len(self.visited)<250,(self.kind,hex(pc));i=self.ins[pc];self.pc=pc;self.visited.append(pc)
   m,o=i.mnemonic,i.operands;nextpc=pc+4
   if m in ['bti','pacibsp']:pass
   elif m in ['autda','xpacd']:self.auth.append(pc)
   elif m=='mov':self.regwrite(i.reg_name(o[0].reg),self.op(i,o[1],self.width(i.reg_name(o[0].reg))))
   elif m=='movk':
    r=i.reg_name(o[0].reg);n=self.width(r);s=o[1].shift.value
    self.regwrite(r,(self.regread(r)&bv(~(65535<<s),n))|bv(o[1].imm<<s,n))
   elif m=='adrp':self.regwrite(i.reg_name(o[0].reg),o[1].imm)
   elif m in ['add','sub','lsl']:
    r=i.reg_name(o[0].reg);n=self.width(r);a,b=self.op(i,o[1],n),self.op(i,o[2],n)
    self.regwrite(r,a+b if m=='add' else a-b if m=='sub' else a<<(b&(n-1)))
   elif m=='sxtw':self.regwrite(i.reg_name(o[0].reg),z3.SignExt(32,bv(self.regread(i.reg_name(o[1].reg)),32)))
   elif m in ['ldr','ldp','str','stp']:
    pair=m in ['ldp','stp'];mo=o[2 if pair else 1];a=self.address_of(i,mo);rs=o[:2] if pair else o[:1]
    for part,r in enumerate(rs):
     reg=i.reg_name(r.reg);n=self.width(reg)//8;at=a+part*n
     if m.startswith('ld'):self.regwrite(reg,self.load(at,n,part))
     else:self.store(at,n,self.regread(reg))
    if i.writeback:
     base=i.reg_name(mo.mem.base);self.regwrite(base,a if o[-1].type!=ARM64_OP_IMM else self.regread(base)+o[-1].imm)
   elif m=='cmp':self.equal=self.op(i,o[0],64)==self.op(i,o[1],64)
   elif m in ['bl','blraa']:self.call()
   elif m=='b':nextpc=o[0].imm&MASK
   elif m=='cbz':
    cond=self.regread(i.reg_name(o[0].reg))==0
    take={0xfffffe000a5051d8:self.case=='task_null',0xfffffe000a505210:self.case!='task_prepare_fail',
     0xfffffe000a505254:self.case=='buffer_null',0xfffffe000a50528c:self.case!='buffer_prepare_fail',
     0xfffffe000a504094:self.case=='zero'}[pc]
    self.guards.append(cond if take else z3.Not(cond))
    if take:nextpc=o[1].imm&MASK
   elif m=='b.eq':self.guards.append(self.equal);nextpc=o[0].imm&MASK
   elif m=='retab':break
   else:raise AssertionError((hex(pc),m,i.op_str))
   pc=nextpc
  return self
 def premises(self):
  out=[(self.sp&15)==0,z3.UGE(self.sp,0x100),z3.ULE(self.sp,bv(MASK-0x100)),self.descriptor!=0,self.buffer!=0]
  for p in [self.user,self.packet,self.output,self.provider,self.address,self.state,self.task,self.staging,
   self.vtask,self.vbuffer,self.vprovider,self.kernel_task,self.page_global,self.kernel_global]:out.extend([p!=0,z3.ULE(p,bv(MASK-0x1000))])
  # Private-frame/object/packet disjointness is a storage premise, not an allocator claim.
  for p in [self.user,self.packet,self.output,self.descriptor,self.buffer]:out.append(z3.Or(z3.ULE(p+0x100,self.sp-0x100),z3.UGE(p,self.sp+0x100)))
  if self.kind=='handler' and not self.output_alias:out.append(z3.Or(z3.ULE(self.packet+16,self.output),z3.ULE(self.output+16,self.packet)))
  if self.kind=='provider' and self.case!='task_null':out.append(self.prepare_task!=0 if self.case=='task_prepare_fail' else self.prepare_task==0)
  if self.kind=='provider' and self.case in ['normal','buffer_prepare_fail']:out.append(self.prepare_buffer!=0 if self.case=='buffer_prepare_fail' else self.prepare_buffer==0)
  return out+self.guards

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set();traces={}
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.premises(),*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.Or(*[z3.Not(x) for x in v.checks],bad));assert s.check()==z3.unsat,label
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2()})
  coverage.append({'label':label,'instruction_instances':len(v.visited),'opaque_calls':len(v.events),'abstract_load_address_obligations':len(v.checks)})
  visited.update(v.visited);print(label,flush=True)
 expected={
  'task_null':['task_descriptor'],
  'task_prepare_fail':['task_descriptor','task_prepare','task_release'],
  'buffer_null':['task_descriptor','task_prepare','buffer_descriptor','task_complete','task_release'],
  'buffer_prepare_fail':['task_descriptor','task_prepare','buffer_descriptor','buffer_prepare','buffer_release','task_complete','task_release'],
  'normal':['task_descriptor','task_prepare','buffer_descriptor','buffer_prepare','buffer_address','copy_in','core','copy_out','buffer_complete','buffer_release','task_complete','task_release']}
 for case,roles in expected.items():
  v=Model(e,'provider',case).run();assert [x[0] for x in v.events]==roles
  traces[case]=[{'role':r,'site':hex(p)} for r,args,p in v.events]
  out=v.core_return if case=='normal' else bv(0xffff5bd4)
  prove(case+'_ordinary_return_preserves_selected_status_and_restores_frame',v,z3.Or(v.regread('x0')!=out,v.regread('sp')!=v.sp,
   *[v.regread('x'+str(j))!=v.initial['x'+str(j)] for j in range(19,30)]))
  task=v.events[0][1]
  prove(case+'_task_address_range_argument_contract',v,same(task[:4],[v.address,bv(v.extent),bv(3),v.task]))
  if case=='normal':
   d={r:args for r,args,p in v.events}
   prove('kernel_buffer_capacity_and_signed_runtime_alignment',v,same(d['buffer_descriptor'][:4],[v.kernel_task,bv(0x13),bv(v.extent),z3.SignExt(32,bv(1,32)<<(v.shift&31))]))
   prove('copy_in_core_copy_out_share_exact_pointer_extent_and_client_state',v,z3.Or(
    same(d['copy_in'][:4],[v.descriptor,bv(0),v.staging,bv(v.extent)]),same(d['core'][:3],[v.staging,v.extent_parameter,v.state]),
    same(d['copy_out'][:4],[v.descriptor,bv(0),v.staging,bv(v.extent)])))
   prove('incoming_provider_extent64_core_custody_with_low32_transfer_extent',v,z3.Or(
    bv(d['core'][1],32)!=v.extent,d['copy_out'][3]!=bv(v.extent),d['core'][1]!=v.extent_parameter),
    [v.extent_parameter!=bv(v.extent)])
   prove('all_completion_release_receivers_and_zero_direction_parameters',v,z3.Or(
    same(d['task_prepare'][:2],[v.descriptor,bv(0)]),same(d['buffer_prepare'][:2],[v.buffer,bv(0)]),
    same(d['buffer_complete'][:2],[v.buffer,bv(0)]),d['buffer_release'][0]!=v.buffer,
    same(d['task_complete'][:2],[v.descriptor,bv(0)]),d['task_release'][0]!=v.descriptor))
   prove('nonzero_core_return_and_short_copy_counts_do_not_change_return_status',v,v.regread('x0')!=v.core_return,
    [bv(v.core_return,32)!=0,v.extent!=0,z3.ULT(v.count_in,bv(v.extent)),z3.ULT(v.count_out,bv(v.extent))])
 for alias in [False,True]:
  for case in ['zero','nonzero']:
   v=Model(e,'handler',case,alias).run();d={r:args for r,args,p in v.events};writes=[(p,a,n,x) for p,a,n,x in v.stores if p in [0xfffffe000a5040b0,0xfffffe000a5040b8]]
   prove('handler_'+str(alias)+'_'+case+'_arguments_status_and_frame',v,z3.Or(
    same(d['provider'],[v.provider,v.address,bv(v.extent),v.state,v.task]),v.regread('x0')!=v.provider_return,v.regread('sp')!=v.sp,
    *[v.regread('x'+str(j))!=v.initial['x'+str(j)] for j in range(19,30)]))
   if case=='zero':
    assert [n for p,a,n,x in writes]==[8,4];dest=v.packet if alias else v.output
    prove('handler_'+str(alias)+'_success_publishes_exact_twelve_descriptor_bytes',v,z3.Or(writes[0][1]!=dest,writes[0][3]!=v.address,
     writes[1][1]!=dest+8,writes[1][3]!=v.extent))
   else:assert not writes and [r for r,args,p in v.events]==['provider','error_log']
 # Algebraic cut: the prior guarded core theorem returns ZE32(raw xor SUCCESS).
 raw=z3.BitVec('TB_raw_status32',32)
 for case in ['zero','nonzero']:
  v=Model(e,'handler',case).run()
  prove('core_to_handler_'+case+'_decoded_status_composition',v,v.regread('x0')!=bv(raw^0x31ae0066),[v.provider_return==bv(raw^0x31ae0066)])
 prior=json.loads(read(ROOT/'userclient_caller_return_audit.json'));rechecked=[]
 for q in prior['source_proofs']:
  if q['label'] not in ['ordinary_cleanup_return_with_equal_canary_decodes_arbitrary_raw_status32','original_argument64_low32_size_codec_saved_for_final_retirement']:continue
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat;rechecked.append({'label':q['label'],'result':'unsat'})
 assert len(rechecked)==2
 assert visited=={int(i['ea'],16) for f in e['functions'].values() for i in f['instructions']} - {0xfffffe000a505320,0xfffffe000a505364}
 # Independently reconstruct the source-address guard for a deliberately altered copy-out extent.
 changed=copy.deepcopy(e);f=changed['functions']['provider'];raw=bytearray.fromhex(f['bytes_hex']);off=0xfffffe000a505338-int(f['start'],16)
 assert raw[off:off+4].hex()=='e30314aa';raw[off:off+4]=bytes.fromhex('030080d2');f['bytes_hex']=raw.hex()
 v=Model(changed,'provider').run();args=next(args for r,args,p in v.events if r=='copy_out')
 s=z3.Solver();s.add(*v.premises(),v.extent!=0,args[3]!=bv(v.extent));assert s.check()==z3.sat
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':R.SCOPE,'source_proofs':qs,'proof_coverage':coverage,'lifecycle_traces':traces,'rechecked_prior_source_proofs':rechecked,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':2,'distinct_proved_instructions':len(visited),
   'proof_instruction_instances':sum(x['instruction_instances'] for x in coverage),'provider_paths':5,'handler_paths':4,
   'authentication_trap_instructions_excluded':2,'altered_copy_extent_counterexample':True},
  'conditional_transfer_boundary_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
