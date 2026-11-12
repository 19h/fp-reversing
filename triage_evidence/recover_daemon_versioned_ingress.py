#!/usr/bin/env python3
"""Source record producer -> adapter -> versioned root, with explicit stops.

O(text words+snapshot+prefix+cases*(visits+effects)) time/space;30 s/query.
Private owners and explicit allocator models; no native API/IPC or PAC.
"""
import copy,json,struct,bisect
from pathlib import Path
from collections import Counter
from hashlib import sha256
import z3
from capstone.arm64_const import ARM64_SFT_ROR,ARM64_OP_REG
from daemon_receive_tools import ROOT,IMAGE,CS,FIXUPS,TABLE,POOL,selected,qword
from daemon_callback_revisit_symbolic import ALLOWED_CALLS
from lskd_values_symbolic import resize,mem,cell
from recover_daemon_iokit_census import text_section
from recover_rpc502_parser_ownership import starts
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_versioned_root as R
P='daemon_versioned_ingress';ENTRY=0x10084c9b8;STOP=0x1008c1760;ADAPTER=0x1004ac814;OWNER=0x6300000000;EXTENT=0x20000
PINS={**R.PINS,'daemon_versioned_root_checks.json':'a5a48b3b767a521c59f86d046de0e39bf482a3391bbc7d42d628869351062853',
 'daemon_versioned_root_audit.json':'daf272f893cea203713992296a905162532dcd6e91864d184c5cd4d406b46a3a',
 'daemon_shared_roots_source.json':'9cee63e167b72ead3991465b701eea55a74c3cb136e6f239000433ef2e6b0f20',
 'daemon_shared_roots_checks.json':'92058c9be2bab89a233d37725e7f7cb88c8c05ef13d2fd953fca911414b0a83f'}
DEPS=R.DEPS+['recover_daemon_versioned_root.py','audit_daemon_versioned_root.py','recover_daemon_iokit_census.py','recover_rpc502_parser_ownership.py']
VARIANTS=['null_B','malloc_failure','clear1','clear2','clear6','prefix','extended','clear_pattern']
SPECS=[('caller',ENTRY,0x10084cb2c),('adapter',ADAPTER,0x1004aca80),('other_adapter',0x10047d180,0x10047d3e8),('unresolved_count_word',0x10063735c,0x100637378),('caller_status_selection',0x1008c1710,0x1008c1768)]

def inputs():
 pins,old=R.inputs()
 for n,d in PINS.items():assert sha(ROOT/n)==d,n
 return pins,old

def source():
 return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(IMAGE.read(a,b-a),a)]}for n,a,b in SPECS]

def census():
 a,n=text_section();raw=IMAGE.read(a,n);bounds,meta=starts();out=[]
 for mod in [0xdbd5,0xfbe5]:
  pattern=struct.pack('<II',0xd2800000|(mod<<5)|17,0xd73f0911);hits=[]
  for j in range(0,len(raw)-7,4):
   if raw[j:j+8]!=pattern:continue
   pc=a+j+4;k=bisect.bisect_right(bounds,pc)-1;hits.append({'call_PC':hex(pc),'compiler_envelope':[hex(bounds[k]),hex(bounds[k+1])],'target_proved_by_modifier':False})
  collision=[{'slot':hex(p),'target':hex(f['target']),'word_hex':IMAGE.read(p,8).hex()}for p,f in sorted(FIXUPS.items())if f'div=0x{mod:04X} 'in f['line']]
  out.append({'modifier16':hex(mod),'pattern_hex':pattern.hex(),'candidates':hits,'collision_slots':collision})
 direct=[]
 for j in range(0,len(raw),4):
  w=struct.unpack_from('<I',raw,j)[0]
  if w&0x7c000000!=0x14000000:continue
  d=w&0x3ffffff;d=d-(1<<26)if d&(1<<25)else d
  if a+j+4*d in [ADAPTER,R.ENTRY]:direct.append({'pc':hex(a+j),'target':hex(a+j+4*d)})
 return {'text_address':hex(a),'text_size_B':n,'text_sha256':sha256(raw).hexdigest(),'literal_patterns':out,'direct_B_BL_to_adapter_or_root':direct,'LC_FUNCTION_STARTS':meta,'scope':'Aligned exact MOVZ X17,imm16;BLRAA X8,X17 and aligned direct B/BL in original __text only. Computed modifiers, other forms, tables and other regions are outside the census; compiler envelopes are not semantic ownership.'}

def banks():
 out=[]
 for l,r,k,add,base in [(0x100fc4230,0x101031fa0,0xf3,0xcebc,TABLE),(0x100fc4130,0x101031ea0,0x4e,0x188,POOL),(0x101031da0,0x100e99900,0x9a,0xce3c,TABLE),(0x100fc4230,0x101031fa0,0xf3,0x8d7,POOL)]:
  row=selected(l,r,k,add,base);row.update(left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex());out.append(row)
 return out

class Extra:
 def operand(self,i,o,n):
  if o.shift.type==ARM64_SFT_ROR:
   assert o.type==ARM64_OP_REG and not o.ext
   return z3.RotateRight(resize(self.read(i.reg_name(o.reg)),n),o.shift.value)
  return super().operand(i,o,n)
 def one(self,i):
  assert i.address!=STOP,'declared caller result-consumer cut'
  if i.mnemonic=='ror':
   self.pc=i.address;o=i.operands;n=self.width(i.reg_name(o[0].reg));self.write(i.reg_name(o[0].reg),z3.RotateRight(self.operand(i,o[1],n),o[2].imm));return
  return super().one(i)

class Run(Extra,R.Run):
 def load(self,a,n):
  at=self.concrete(resize(a,64),'read address')
  if OWNER<=at<at+n<=OWNER+EXTENT:
   for j in range(at,at+n):
    if j not in self.bytes:self.bytes[j]=z3.BitVec('unknown_'+hex(j),8)
  return super().load(a,n)
 def store(self,a,n,x,pc):
  at=self.concrete(resize(a,64),'write address')
  if not OWNER<=at<at+n<=OWNER+EXTENT:return super().store(a,n,x,pc)
  if self.transaction:
   for j in range(at,at+n):self.undo_bytes.setdefault(j,(j in self.bytes,self.bytes.get(j),j in self.changed))
  x=resize(x,n*8);self.events.append({'kind':'write','address':hex(at),'size_bytes':n,'value':self.shape(x,n)})
  for j in range(n):self.bytes[at+j]=z3.simplify(z3.Extract(8*j+7,8*j,x));self.changed.add(at+j)

class Algebra(Extra,R.Algebra):pass

def configuration(epoch,name):
 if name in ['exclude47d','adapter_prefix']:
  c=R.configuration(epoch,'clear1');c['entry_SP']=hex(int(c['entry_SP'],16)+80);c.update(kind='prefix',name=name,entry=hex(0x10047d180 if name=='exclude47d'else ADAPTER));return c
 s=OWNER+0x4000+epoch*0x1000;cap={'clear2':2,'clear6':0x42,'prefix':8,'extended':0x28}.get(name,0)
 return {'epoch':epoch,'name':name,'kind':'caller','entry':hex(ENTRY),'caller_SP':hex(s),'fresh_owner':{'address':hex(OWNER),'size_bytes':EXTENT},'capabilities_u32':hex(cap),'input_A':hex(s+0x5c48),'input_B':hex(OWNER+0x18000)if name!='null_B'else'0x0','input_extent_B':256,'input_fill_byte':17 if name=='clear_pattern'else 0,'malloc_success':name!='malloc_failure','allocation':hex(0x6500100000+80000),'allocation_B':32,
 'u64_cells':{hex(s+k):hex(x)for k,x in {0x9d0:0x6cf4,0x9d8:TABLE,0x9c0:0x1010c4670,0x9c8:0x1010b8dc8,0x960:0x101031ea0,0x968:0x100fc4130,0x9a8:0x101031fa0,0x9b0:0x100fc4230,0xfc8:OWNER+0x18000 if name!='null_B'else 0,0x16d0:0}.items()},
 'registers':{'sp':hex(s),'x8':'0xa6','x9':'0xa5cd4cf','x30':hex(R.RETURN)}}

def overlay(v,c):
 if c['kind']=='prefix':R.overlay(v,c);return
 for at in range(OWNER,OWNER+EXTENT):v.bytes.pop(at,None)
 for a,x in c['u64_cells'].items():R.put(v,int(a,16),8,int(x,16))
 for n in ['input_A','input_B']:
  a=int(c[n],16)
  if a:
   for at in range(a,a+c['input_extent_B']):R.put(v,at,1,c['input_fill_byte'])
 R.put(v,0x1010b6394,4,int(c['capabilities_u32'],16)^0xc49697f0)
 for n,x in c['registers'].items():v.regs[n]=z3.BitVecVal(int(x,16),64)
 v.steps=[];v.pool={};v.cache={};v.fixups=set();v.zero_reads=[];v.changed=set();v.definitions=[];v.origins={};v.unknown_inputs_used={}

def obligations():
 r,s,c,phase,pointer=z3.BitVecs('ingress_record64 ingress_SP64 ingress_seed64 ingress_phase64 ingress_input64',64);qs=[]
 def add(n,p):qs.append((n,p))
 v=Algebra();v.seed('sp',r-0x10cb8);v.seed('w15',resize(phase,32));v.seed('x11',pointer);v.run_block(0x10084c9c8,0x10084ca08)
 k=resize(R.key(r),32)
 add('source_caller_key_matches_root_for_all_addresses',v.read('w12')!=k)
 v.seed('w12',k);v.run_block(0x10084ca08,0x10084ca3c)
 add('source_caller_count_tag_and_operation',z3.Or(cell(v,r,4)+k!=0x73113b31,cell(v,r+4,4)-k!=resize(phase,32)+0x1a26,cell(v,r+0x10,8)!=r-0x10cb8+0x5c48,cell(v,r+0x18,8)!=pointer))
 add('operation871a_unique_caller_phase',(resize(phase,32)+0x1a26==0x871a)!=(resize(phase,32)==0x6cf4))
 v=Algebra();v.seed('sp',s)
 for j in [19,20,21,22,29,30]:v.seed('x'+str(j),z3.BitVec('ingress_saved_'+str(j),64))
 v.run_block(ADAPTER+4,0x1004ac82c);add('adapter_fixed_frame',z3.Or(v.read('sp')!=s-64,v.read('x29')!=s-16))
 v=Algebra();v.seed('x21',c);v.run_block(0x1004ac934,0x1004ac93c);v.run_block(0x1004ac940,0x1004ac944);add('source_adapter_next_seed',v.read('x16')!=c*0x2edd+1)
 new=c*0x2edd+1;v=Algebra();v.seed('x16',new);v.seed('sp',s-64);v.seed('x21',c);v.run_block(0x1004ac984,0x1004ac9a8)
 reserve=16*(z3.LShR(new,60)+1);temp=s-64-reserve
 assert len(v.stores)==1
 add('adapter_dynamic_temp_and_bias',z3.Or(v.read('sp')!=temp,v.read('x20')!=temp,v.stores[0]['address']!=temp,v.stores[0]['value']!=c-0xb0))
 add('adapter_reserve_range',z3.Or(z3.ULT(reserve,16),z3.UGT(reserve,256),reserve&15!=0))
 add('root_increment_cancels_adapter_bias',(c-0xb0)+0xb0!=c)
 v=Algebra();v.seed('x20',pointer);v.seed('x19',r);v.seed('w21',resize(c,32));mem(v,pointer,4,resize(phase,32));v.run_block(0x1004aca5c,0x1004aca6c)
 delta=z3.ZeroExt(48,z3.Extract(15,0,phase-c))<<4;add('source_adapter_return_delta',cell(v,r,8)!=delta)
 add('return_delta_zero_iff_low16_equal',(delta==0)!=(z3.Extract(15,0,phase)==z3.Extract(15,0,c)))
 v=Algebra();status=z3.BitVec('ingress_result32',32);v.seed('w8',status);v.seed('w19',0x6cf4-0xfc2);v.seed('x11',pointer);v.seed('sp',s);v.run_block(0x1008c1710,0x1008c1748)
 add('caller_encoded_zero_comparison',z3.Or(v.read('w8')!=z3.If(status==0x8b3dc651,z3.BitVecVal(1,32),z3.BitVecVal(0,32)),cell(v,s+0x16d0,8)!=pointer-0x480))
 v.run_block(0x1008c1748,0x1008c1758);success=((((0x5d32^0x588e)*19)^0x6c83)^0x5d32)&0xffffffff
 add('caller_status_branch_index',v.read('w8')!=z3.If(status==0x8b3dc651,z3.BitVecVal(success,32),z3.BitVecVal(0x5d32,32)))
 # Compose the proved caller-key lemma to avoid a monolithic multiply query.
 rows=[]
 for n,p in qs:
  q=z3.Solver();q.set(timeout=30000);q.add(p);result=str(q.check());assert result=='unsat',(n,result);rows.append({'label':n,'query':q.to_smt2(),'result':result})
 return rows

def main():
 pins,old=inputs();base=Run.from_snapshot(pins['daemon_callback_revisit_snapshot.json']);epochs=[j for j,r in enumerate(old['steps'])if r['pc']=='0x100add594'];previous=0;cases=[];totals=Counter()
 for epoch,end in enumerate(epochs):
  R.H.advance(base,old['steps'][previous:end]);previous=end
  for name in ['exclude47d','adapter_prefix']+VARIANTS:
   c=configuration(epoch,name);v=copy.copy(base);v.bytes=base.bytes.copy();v.regs=base.regs.copy();overlay(v,c);initial={n:v.shape(x,16 if n.startswith('q')else 8)for n,x in v.regs.items()};flags=sum(1<<(31-j)for j,x in enumerate([v.n,v.z,v.carry,v.overflow])if z3.is_true(x));models=[];start=int(c['entry'],16)
   ALLOWED_CALLS.difference_update([ADAPTER,R.ENTRY,0x100455c30,0x100439874])
   if c['kind']=='caller':ALLOWED_CALLS.update([ADAPTER,R.ENTRY,0x100455c30,0x100439874])
   for attempt in range(3):
    b=v.run_revisit(start,limit=200000)
    if c['kind']=='caller'and b['kind']=='before_uninspected_call'and int(b['pc'],16)in [R.MALLOC,R.FREE]:models.append(R.model(v,c,int(b['pc'],16),len(models)));start=int(b['pc'],16)+4;continue
    break
   if c['kind']=='prefix':assert b['kind']=='before_uninspected_call'and b['target']==hex(0x10046fc5c if name=='exclude47d'else R.ENTRY)
   else:
    assert b['kind']=='before_unresolved_source_effect'and not b['uncommitted_events'],b
    assert int(b['pc'],16)==(0x10063736c if name in ['prefix','extended']else STOP),b
    if int(b['pc'],16)==STOP:assert b['reason']=='declared caller result-consumer cut';b['kind']='declared_after_caller_status_selection'
   assert not v.definitions
   counts={'source_visits':len(v.steps),'source_pool_entries':len(v.pool),'read_events':sum(e['kind']=='read'for r in v.steps for e in r['events']),'write_events':sum(e['kind']=='write'for r in v.steps for e in r['events']),'API_models':len(models)};totals.update(counts)
   trace={'steps':v.steps,'boundary':b,'source_pool':v.pool,'used_fixups':list(map(hex,sorted(v.fixups))),'initial_registers':initial,'initial_NZCV':flags}
   cases.append({'configuration':c,'prefix_source_visits':end,'trace':trace,'API_models':models,'counts':counts});print(json.dumps({'epoch':epoch,'variant':name,**counts}),flush=True)
 used={int(a,16)for case in cases for a in case['trace']['used_fixups']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':R.H.THIN,'parent_pins':PINS,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source_regions':source(),'source_fixups':R.verify_fixups(used),'source_proofs':obligations(),'bounded_census':census(),'bank_rules':banks(),'cases':cases,'verified_counts':{'cases':len(cases),'epochs':2,'variants_per_epoch':10,**dict(totals)},
 'prefix_reexecuted':False,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'live_IDA_claim':False,'native_caller_admission_established':False,'complete_IOKit_buffer_join_established':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)

if __name__=='__main__':main()
