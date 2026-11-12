#!/usr/bin/env python3
"""Continue the declared private nested-helper state through original A64 bytes.

O(restored prefixes+cases*(visits+effects)) time/space;30 s/proof query.
No native API, IPC, hardware PAC or admitted upstream state is asserted.
"""
import copy,json
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,IMAGE,CS,TABLE
from lskd_values_symbolic import resize,mem,cell
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_remainder_preparation as Parent
P='daemon_nested_helper_processing';ENTRY=Parent.STOP;RETURN=0x10049d430;STOP=0x100383700
PINS={**Parent.PINS,
 'daemon_remainder_preparation_checks.json':'36251efa700d49f6ca3fa384607a77748a7923ede4247b99ef3065ad0f4029b2',
 'daemon_remainder_preparation_audit.json':'3adc6dae4e51a8a2c1b966dfc82508fd4f3603fc7cb8ceb74cce8697b85f7e33'}
DEPS=Parent.DEPS+['recover_daemon_remainder_preparation.py','audit_daemon_remainder_preparation.py']
PROFILES={'baseline':None,'block_bit0':0x6c8,'pointer0_bit0':0x610,'pointer20_bit0':0x600}
SPECS=[('pending_entry_dispatch',ENTRY,0x1004237a4),('initial_selector',0x1000bba74,0x1000bbad8),
 ('count_obfuscation',0x100423614,0x10042363c),('count_projection',0x1000896dc,0x1000896e8),
 ('block_input_loop_tail',0x1000bc264,0x1000bc2d4),('pointer0_decode_loop_tail',0x10015d3cc,0x10015d430),
 ('block_output_loop',0x10002c010,0x10002c0f0),('result_and_epilogue',0x10015f9dc,0x10015fa3c),
 ('caller_result_read',RETURN,0x10049d440),('caller_status_selection',0x10062369c,0x1006236ec),
 ('original_EXTR_site',0x100117e20,0x100117e38)]

class Run(Parent.R.Run):
 def one(self,i):
  assert i.address!=STOP,'declared after caller status selection'
  if i.mnemonic=='extr':
   self.pc=i.address;o=i.operands;n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);b=self.operand(i,o[2],n);k=o[3].imm
   assert 0<=k<n
   self.write(i.reg_name(o[0].reg),z3.Extract(k+n-1,k,z3.Concat(a,b)));return
  if i.mnemonic in ['ldurb','sturb']:
   self.pc=i.address;o=i.operands;assert not i.writeback;a=self.address(i,o[1])
   if i.mnemonic=='ldurb':self.write(i.reg_name(o[0].reg),self.load(a,1))
   else:self.store(a,1,self.read(i.reg_name(o[0].reg)),i.address)
   return
  return super().one(i)

def inputs():
 pins,old,ingress=Parent.inputs()
 for name,digest in PINS.items():assert sha(ROOT/name)==digest,name
 previous=json.loads(read(ROOT/'daemon_remainder_preparation_checks.json'))
 return pins,old,ingress,previous

def restore(snapshot,old,original,previous):
 v,cut=Parent.restore(snapshot,old,original);v.__class__=Run
 Parent.R.R.put(v,int(previous['configuration']['allocation'],16)+16,4,int(previous['configuration']['declared_raw_object_word'],16))
 Parent.R.R.H.advance(v,previous['trace']['steps']);return v,cut

def source():
 out=[]
 for name,a,b in SPECS:
  raw=IMAGE.read(a,b-a);ii=list(Parent.Parent.DEC.disasm(raw,a));assert len(ii)*4==len(raw)
  out.append({'name':name,'start':hex(a),'end':hex(b),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 return out

def obligations():
 r,g,f,j,ptr=z3.BitVecs('nested_record64 nested_helper_frame64 nested_root_frame64 nested_index64 nested_pointer64',64)
 status,byte,step,phase=z3.BitVecs('nested_status32 nested_byte32 nested_step32 nested_phase32',32);qs=[]
 count=z3.BitVec('nested_normalized_count32',32);v=Parent.R.Algebra();v.seed('sp',g);v.seed('w16',count);v.run_block(0x100423614,0x10042363c);v.seed('w0',phase);v.run_block(0x1000bba74,0x1000bbac4);v.run_block(0x1000896dc,0x1000896e8)
 qs.append(('selected_input_loop_count_is_normalized_control_for_all_u32',v.read('x0')!=z3.ZeroExt(32,count)))
 v=Parent.R.Algebra();v.seed('sp',g);v.seed('w9',status);mem(v,g+0x20,8,r);v.run_block(0x10015f9dc,0x10015fa04)
 qs.append(('record_status_result_is_guard_selected_word',cell(v,r+0x1c,4)!=z3.If(status==0x0c67c7c7,z3.BitVecVal(0x8b3dc651,32),z3.BitVecVal(0x74c29d89,32))))
 v=Parent.R.Algebra();v.seed('sp',g);saved={n:z3.BitVec('nested_saved_'+n,64)for n in ['x'+str(k)for k in range(19,31)]}
 for offset,n in [(0x290,'x28'),(0x298,'x27'),(0x2a0,'x26'),(0x2a8,'x25'),(0x2b0,'x24'),(0x2b8,'x23'),(0x2c0,'x22'),(0x2c8,'x21'),(0x2d0,'x20'),(0x2d8,'x19'),(0x2e0,'x29'),(0x2e8,'x30')]:mem(v,g+offset,8,saved[n])
 v.run_block(0x10015fa1c,0x10015fa38)
 qs.append(('epilogue_restores_fixed_frame_and_saved_GPRs',z3.Or(v.read('sp')!=g+0x2f0,*[v.read(n)!=x for n,x in saved.items()])))
 v=Parent.R.Algebra();v.seed('x29',f+0x970);mem(v,f+0x8d8+0x1c,4,status);v.run_block(RETURN,RETURN+4)
 qs.append(('caller_reads_record_status_at_1c',v.read('w28')!=status))
 v=Parent.R.Algebra();v.seed('w20',0x553e);v.seed('w28',status);v.run_block(0x10062369c,0x1006236d4)
 qs.append(('caller_status_selector_for_all_status_words',v.read('w8')!=z3.If(status==0x8b3dc651,z3.BitVecVal(0x554a,32),z3.BitVecVal(0x553e,32))))
 v=Parent.R.Algebra()
 for n,x in [('x0',j),('x14',ptr),('w17',byte),('w4',step),('w15',phase)]:v.seed(n,x)
 v.run_block(0x1000bc2b0,0x1000bc2c4)
 qs.append(('input_loop_writes_one_byte_and_selects_zero_index_exit',z3.Or(cell(v,ptr+j,1)!=z3.Extract(7,0,byte),v.read('w17')!=(phase^z3.If(j==0,step,z3.BitVecVal(0,32))))))
 v=Parent.R.Algebra()
 for n,x in [('x10',j),('x14',ptr),('w17',byte),('w4',step),('w8',phase)]:v.seed(n,x)
 mem(v,ptr+j-1,1,z3.Extract(7,0,byte));v.run_block(0x10002c010,0x10002c018)
 # The intervening original body contains no flag-writing instruction.
 body=list(Parent.Parent.DEC.disasm(IMAGE.read(0x10002c018,0x10002c0cc-0x10002c018),0x10002c018));assert all(not i.update_flags for i in body)
 v.run_block(0x10002c0d0,0x10002c0e0)
 qs.append(('output_loop_decrements_writes_byte_and_selects_zero_exit',z3.Or(v.read('x10')!=j-1,cell(v,ptr+j-1,1)!=z3.Extract(7,0,byte),v.read('w17')!=(phase^z3.If(j-1==0,step,z3.BitVecVal(0,32))))))
 out=[]
 for label,p in qs:
  s=z3.Solver();s.set(timeout=30000);s.add(p);result=str(s.check());assert result=='unsat',(label,result);out.append({'label':label,'query':s.to_smt2(),'result':result})
 return out

def main():
 pins,old,ingress,previous=inputs();cases=[];totals=Counter()
 for prior in previous['cases']:
  c=prior['configuration']
  if c['declared_decoded_object_word']:continue
  original=next(v for v in ingress['cases']if v['configuration']['epoch']==c['epoch']and v['configuration']['name']==c['parent_variant'])
  base,cut=restore(pins['daemon_callback_revisit_snapshot.json'],old,original,prior);f=int(c['caller_SP'],16)-0x9d0
  for profile,offset in PROFILES.items():
   v=copy.copy(base);v.bytes=base.bytes.copy();v.regs=base.regs.copy();overlays=[]
   if offset is not None:
    a=f+offset;oldbyte=v.concrete(v.bytes[a],'declared operand byte');newbyte=oldbyte^1;Parent.R.R.put(v,a,1,newbyte);overlays.append({'address':hex(a),'old_byte_hex':bytes([oldbyte]).hex(),'new_byte_hex':bytes([newbyte]).hex(),'xor_mask_u8':1})
   config={**c,'preparation_variant':c['name'],'name':c['name']+'_'+profile,'operand_profile':profile,'operand_overlays':overlays,'entry':hex(ENTRY),'preparation_prefix_source_visits':len(prior['trace']['steps'])}
   v.steps=[];v.pool={};v.cache={};v.fixups=set();v.zero_reads=[];v.changed=set();v.definitions=[];v.origins={};v.unknown_inputs_used={}
   initial={n:v.shape(x,16 if n.startswith('q')else 8)for n,x in v.regs.items()};flags=sum(1<<(31-j)for j,x in enumerate([v.n,v.z,v.carry,v.overflow])if z3.is_true(x))
   b=v.run_revisit(ENTRY,limit=200000);assert not v.definitions and b['pc']==hex(STOP)and b['reason']=='declared after caller status selection'and not b['uncommitted_events'],b
   counts={'source_visits':len(v.steps),'source_pool_entries':len(v.pool),'read_events':sum(e['kind']=='read'for r in v.steps for e in r['events']),'write_events':sum(e['kind']=='write'for r in v.steps for e in r['events'])};totals.update(counts)
   cases.append({'configuration':config,'trace':{'steps':v.steps,'boundary':b,'source_pool':v.pool,'used_fixups':list(map(hex,sorted(v.fixups))),'initial_registers':initial,'initial_NZCV':flags},'API_models':[],'counts':counts})
   print(json.dumps({'epoch':config['epoch'],'variant':config['name'],**counts,'boundary_PC':b['pc']}),flush=True)
 used={int(a,16)for case in cases for a in case['trace']['used_fixups']}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':Parent.R.R.H.THIN,'parent_pins':PINS,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source_regions':source(),'source_proofs':obligations(),'source_fixups':Parent.R.R.verify_fixups(used),'caller_branch_slots':Parent.R.R.verify_fixups({TABLE+n*8 for n in [0x524a,0x553e,0x554a]}),'cases':cases,'verified_counts':{'cases':len(cases),'epochs':2,'variants_per_epoch':8,**dict(totals)},
  **{k:False for k in ['prefixes_reexecuted','native_target_executed','native_API_executed','IDB_mutated','live_IDA_claim','actual_partial_fixture_resumed','native_caller_admission_established','native_daemon_kext_pairing_established','full_goal_complete']}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)

if __name__=='__main__':main()
