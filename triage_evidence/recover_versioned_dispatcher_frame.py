#!/usr/bin/env python3
"""Complete compiler-bounded dispatcher census and symbolic post-frontier slice.

Pinned private receipts remain stopped before their unspecified frame load.
An independent source lift carries an arbitrary u32 in W24; no guest fill is
consumed. O(receipt bytes+I+C*V+256R) time/space, plus 30 s/query. No native
allocator, IPC, process or IDA operation executes.
"""
import json,struct
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM,ARM64_OP_REG,ARM64_OP_IMM,ARM64_EXT_UXTB,ARM64_EXT_SXTW
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,selected
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from lskd_values_symbolic import Lift,part,mem,cell,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_versioned_core_preparation as Parent

P='versioned_dispatcher_frame'
PIN='b5a8adb34c380be6daf899d7b481a7a55e7e814b353ee24a39c076f88d781941'
START=0xfffffe000a5a5470;END=0xfffffe000a5a9324
FRONTIER=0xfffffe000a5a6e5c;CALL=0xfffffe000a5a6f74
DC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DC.detail=True

def census(source):
 accesses=[];aliases=[];spwrites=[];crossings=[];count=0
 for i in DC.disasm(bytes.fromhex(source['bytes_hex']),START):
  count+=1;ops=i.operands
  if i.mnemonic in ['add','sub']and len(ops)==3 and ops[0].type==ARM64_OP_REG and i.reg_name(ops[0].reg)=='sp':spwrites.append(hex(i.address))
  if i.mnemonic=='b'and i.address<0xfffffe000a5a72bc<=ops[0].imm&((1<<64)-1):crossings.append({'pc':hex(i.address),'target':hex(ops[0].imm&((1<<64)-1))})
  if i.address<0xfffffe000a5a5494 or 0xfffffe000a5a729c<=i.address<0xfffffe000a5a72bc:continue
  if i.mnemonic.startswith(('str','stur','stp','ldr','ldur','ldp'))and ops[-1].type==ARM64_OP_MEM:
   o=ops[-1];base=i.reg_name(o.mem.base)
   if base in ['sp','fp','x29']and not o.mem.index:
    off=o.mem.disp+(0x250 if base!='sp'else 0);reg=i.reg_name(ops[0].reg)
    n=(1 if i.mnemonic.endswith('b')else 2 if i.mnemonic.endswith('h')else 4 if reg.startswith('w')or i.mnemonic=='ldrsw'else 16 if reg.startswith('q')else 8)*(2 if i.mnemonic in ['stp','ldp']else 1)
    if off<0x138 and off+n>0x130:accesses.append({'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'body_SP_offset':hex(off),'size_bytes':n,'write':i.mnemonic.startswith(('str','stur','stp'))})
  if i.mnemonic in ['add','sub']and len(ops)==3 and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM and i.reg_name(ops[1].reg)in ['sp','fp','x29']:
   off=(0 if i.reg_name(ops[1].reg)=='sp'else 0x250)+(ops[2].imm<<ops[2].shift.value)*(1 if i.mnemonic=='add'else -1)
   if 0x130<=off<0x138:aliases.append({'pc':hex(i.address),'operands':i.op_str,'body_SP_offset':hex(off)})
 assert count==(END-START)//4 and spwrites==['0xfffffe000a5a5490','0xfffffe000a5a729c']
 writers=[a['pc']for a in accesses if a['write']and int(a['body_SP_offset'],16)<0x134]
 assert writers==['0xfffffe000a5a76f0','0xfffffe000a5a8150','0xfffffe000a5a8d58']
 return {'instruction_words':count,'body_SP_changes':spwrites,'slot_accesses':accesses,'direct_pointer_producers':aliases,'direct_branches_beyond_previous_capture':crossings,'computed_alias_writers_excluded':True,'native_uninitialized_read_proved':False}

def obligations(source):
 c={'spans':[source]};out=[];counts={};F=0x51010000;T=z3.BitVec('dispatcher_carried_word32',32)
 def run(label,a,z,seeds=(),memory=()):
  v=Lift(part(c,label,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(label);counts[label]=v.count;return v
 S=z3.BitVec('dispatcher_helper_status32',32)
 v=run('helper_status_route',0xfffffe000a5a6e24,0xfffffe000a5a6e54,[('w22',0x13e),('w2',S)])
 out.append(('helper_status_route',z3.Or(v.read('w8')!=0xbb1,v.read('w9')!=z3.If(S==0x31ae0066,z3.BitVecVal(0x5a2,32),z3.BitVecVal(0x13e,32)))))
 D=z3.BitVec('dispatcher_inputB64',64);N=z3.BitVec('dispatcher_count32',32)
 v=run('input_pointer_count_route',0xfffffe000a5a6e6c,0xfffffe000a5a6e94,[('w8',0xbb1),('x23',D),('x29',F+0x250)],[(F+0x1b8,4,N)])
 out.append(('input_pointer_count_route',z3.Or(v.read('w19')!=0x93d,v.read('w8')!=z3.If(z3.And(D!=0,N!=0),z3.BitVecVal(0xbb8,32),z3.BitVecVal(0xbb1,32)))))
 for label,a in [('first_spill_relay',0xfffffe000a5a76ec),('second_spill_relay',0xfffffe000a5a8d54)]:
  v=run(label,a,a+8,[('sp',F)],[(F+0x134,4,T)]);out.append((label,cell(v,F+0x130,4)!=T))
 v=run('save_W24',0xfffffe000a5a8150,0xfffffe000a5a8154,[('sp',F),('w24',T)]);out.append(('save_W24',cell(v,F+0x130,4)!=T))
 v=run('restore_W24',0xfffffe000a5a8254,0xfffffe000a5a8258,[('sp',F)],[(F+0x130,4,T)]);out.append(('restore_W24',v.read('w24')!=T))
 queries=[]
 for label,q in out:
  s=z3.Solver();s.set(timeout=30000);s.add(q);assert s.check()==z3.unsat,label;queries.append({'label':label,'result':'unsat','query':s.to_smt2()})
 return queries,counts

class Slice(Lift):
 def __init__(self,k,row):
  super().__init__({});self.k=k;self.state={};self.known=set();self.loads=[];self.observables=[];self.trace=[];self.edges=[]
  for a,h in row['initial_cells'].items():
   for j,b in enumerate(bytes.fromhex(h),int(a,16)):self.state[j]=b;self.known.add(j)
  for e in row['source_writes']:
   for j,b in enumerate(bytes.fromhex(e['after_hex']),int(e['address'],16)):self.state[j]=b;self.known.add(j)
  b=row['boundary'];assert b['pc']==hex(FRONTIER)and b['known_bytes']==0
  for j,v in enumerate(b['registers31']):self.seed('x'+str(j),int(v,16))
  self.seed('sp',int(b['SP'],16));self.opaque=z3.BitVec('unresolved_frame_word32',32);self.seed('w24',self.opaque)
  a=int(b['address'],16);assert not any(j in self.known for j in range(a,a+4));self.unknown_address=a
 def operand(self,i,o,n):
  if o.ext in [ARM64_EXT_UXTB,ARM64_EXT_SXTW]:
   v=self.read(i.reg_name(o.reg));v=z3.ZeroExt(n-8,resize(v,8))if o.ext==ARM64_EXT_UXTB else z3.SignExt(n-32,resize(v,32));return v<<o.shift.value
  return super().operand(i,o,n)
 def address(self,i,o):
  a=self.read(i.reg_name(o.mem.base))+o.mem.disp
  if o.mem.index:
   x=self.read(i.reg_name(o.mem.index));x=z3.SignExt(32,resize(x,32))if o.ext==ARM64_EXT_SXTW else resize(x,64);a+=x<<o.shift.value
  return z3.simplify(a)
 def concrete(self,v):
  v=z3.simplify(v);assert z3.is_bv_value(v),('unknown observable',v.sexpr());self.observables.append(v);return v.as_long()
 def load(self,a,n):
  at=self.concrete(a);raw=bytearray()
  for j in range(at,at+n):
   if Parent.Parent.P<=j<Parent.Parent.P+0x20000:assert j in self.known,('unspecified private read',hex(self.pc),hex(j))
   if j in self.state:raw.append(self.state[j])
   else:raw.extend(IMAGE.read(j,1))
  fixup=None
  if not any(j in self.state for j in range(at,at+n)):
   original=self.k.read(at,n)
   if original!=raw:
    assert n==8,('non-pointer normalization',hex(self.pc),hex(at),n)
    fixup=pointer(self.k,at);assert int(fixup['target'],16)==int.from_bytes(raw,'little')
  v=z3.BitVecVal(int.from_bytes(raw,'little'),n*8);self.loads.append({'pc':hex(self.pc),'address':hex(at),'size_bytes':n,'bytes_hex':raw.hex(),'original_pointer_fixup':fixup});return v
 def store(self,*args):raise AssertionError('post-frontier slice must not write')
 def run_slice(self):
  pc=FRONTIER+4
  while True:
   assert len(self.trace)<100;raw=self.k.read(pc,4);assert raw==IMAGE.read(pc,4);i=next(DC.disasm(raw,pc));self.pc=pc
   if i.mnemonic=='blraa':
    assert pc==CALL;target=self.concrete(self.read(i.op_str.split(',')[0]));modifier=self.concrete(self.read('x17'));arg=self.concrete(self.read('x0'));break
   self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
   if i.mnemonic=='braa':
    target=self.concrete(self.read(i.op_str.split(',')[0]));modifier=self.concrete(self.read('x17'));edge={'pc':hex(pc),'target':hex(target),'modifier':hex(modifier)};self.edges.append(edge);pc=target;continue
   if i.mnemonic=='bti':pc+=4;continue
   if i.mnemonic=='adrp':self.write(i.reg_name(i.operands[0].reg),i.operands[1].imm&((1<<64)-1));pc+=4;continue
   self.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':raw.hex()}]};super().run('one');pc+=4
  assert z3.eq(z3.simplify(self.read('w24')),self.opaque)
  other=z3.BitVec('alternative_frame_word32',32);s=z3.Solver();s.set(timeout=30000);s.add(z3.Or(*[v!=z3.substitute(v,(self.opaque,other))for v in self.observables]));assert s.check()==z3.unsat
  ptrs=[]
  for edge in self.edges+[{'pc':hex(CALL),'target':hex(target),'modifier':hex(modifier)}]:
   candidates=[l for l in self.loads if l['size_bytes']==8 and int.from_bytes(bytes.fromhex(l['bytes_hex']),'little')==int(edge['target'],16)]
   # The first transfer's pointer was loaded before the preserved frontier.
   if not candidates:slot=TABLE+8*0x5a2
   else:slot=int(candidates[-1]['address'],16)
   p=pointer(self.k,slot);assert p['target']==edge['target']and p['authenticated']and p['diversity']==edge['modifier'];ptrs.append(p)
  return {'source_trace':self.trace,'source_reads':self.loads,'source_transfers':self.edges,'pending_call':{'pc':hex(CALL),'bytes_hex':self.k.read(CALL,4).hex(),'target':hex(target),'modifier':hex(modifier),'X0':hex(arg),'executed':False},'original_transfer_pointers':ptrs,'word_provenance':'arbitrary symbolic u32; no concrete value or initialized frame cell supplied','unknown_frame_address':hex(self.unknown_address),'W24_still_symbolic':True,'observable_independence':{'result':'unsat','query':s.to_smt2(),'observables':len(self.observables)},'guest_continued':False}

def build():
 assert sha(ROOT/'versioned_core_preparation_checks.json')==PIN
 prior=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));assert prior['generator_sha256']==sha(Parent.__file__)and prior['dependencies']=={n:sha(ROOT/n)for n in Parent.DEPS};k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');source=function(k,e,START)
 assert int(source['end'],16)==END and bytes.fromhex(source['bytes_hex'])==IMAGE.read(START,END-START)
 qs,counts=obligations(source);rows=[];totals=Counter()
 for ix,row in enumerate(prior['cases']):
  if row['configuration']['mode32']!=2:continue
  totals.update(Parent.Parent.audit_bytes(row,k));v=Slice(k,row);out=v.run_slice();out.update(parent_case_index=ix,configuration=row['configuration'],operand_profile=row['source_payload']['operand_profile']);rows.append(out)
 rules=[]
 for label,l,r,key,add,base,bias in [('typed_allocator',0xfffffe0007949dd0,0xfffffe000792fbc0,0x73,0xecc,TABLE,0),('stream_type_view',0xfffffe0007949fd0,0xfffffe000792ffc0,0x37,0x199,POOL,-12)]:
  rule=selected(l,r,key,add,base,bias);rule.update(label=label,base=hex(base),left256_hex=k.read(l,256).hex(),right256_hex=k.read(r,256).hex(),original_pointer=pointer(k,int(rule['slot'],16)));assert k.read(l,256)==IMAGE.read(l,256)and k.read(r,256)==IMAGE.read(r,256);assert(int(rule['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(rule['target'],16);rules.append(rule)
 a=int(rules[1]['target'],16);raw=IMAGE.read(a,64);ps=[pointer(k,a+off)for off in [16,32]];flags,n=struct.unpack_from('<II',raw,40);name=k.read(int(ps[0]['target'],16),80).split(b'\0')[0].decode();assert(name,flags,n)==('site.FPByteArrayStreamInternal',0x64,32)
 for row in rows:assert row['pending_call']['target']==rules[0]['target']and row['pending_call']['X0']==hex(a)
 return {'scope':__doc__,'generator_sha256':sha(__file__),'parent_checks_sha256':PIN,'kernel_collection_sha256':k.sha256,'source_function':source,'frame_census':census(source),'source_proofs':qs,'source_lift_counts':counts,'cases':rows,'selected_bank_rules':rules,'allocation_type_view':{'address':hex(a),'normalized64_hex':raw.hex(),'pointer_fields':ps,'name':name,'flags':hex(flags),'allocation_size_bytes':n,'object_field_layout':'unknown'},'allocator_symbols':k.symbols([int(rules[0]['target'],16)]),'verified_counts':{'retained_mode2_cases':len(rows),'compiler_function_instruction_words':(END-START)//4,'slot130_direct_store_sites':3,'source_queries_unsat':len(qs),'source_lift_instructions':sum(counts.values()),'symbolic_slice_queries_unsat':len(rows),'symbolic_slice_instruction_visits':sum(len(r['source_trace'])for r in rows),'symbolic_slice_read_bytes':sum(l['size_bytes']for r in rows for l in r['source_reads']),'original_transfer_pointers_checked':sum(len(r['original_transfer_pointers'])for r in rows),'exhaustive_bank_inputs':512,**totals},'new_guest_execution':False,'new_model_memory_writes':0,'native_target_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 obj=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps(obj['verified_counts']),flush=True)
