#!/usr/bin/env python3
"""Original map/root construction feeds exact state into type2 consumer.
Allocation zeroing, locks and lower range resolver are explicit models.
O(visits+RAM+effects), O(image+RAM+journals). No native VM/IPC effects.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_type2_copyout import Probe as Parent,P,SIZE,SP,HALT,KMAP,COPY,NEW,THREAD,OUT
from probe_rpc502_vm_handoff import decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='kernel_map_store_init';ROOTPAGE=0xfffffe0003000000;MZ=P+0xb2000;MA=P+0xb2100;RZ=P+0xb2200;RA=P+0xb2300;EXTSTORE=P+0xb4000;COUNTER=0xfffffe000cb810e8
class Probe(Parent):
 def __init__(self,im,c,src,seed,factory,producer=None,index=None):
  super().__init__(im,{'test':'constructor_handoff','resolver_result':c.get('resolver_result')},src,seed,factory);self.aux_regions=list(self.aux_regions)+[(ROOTPAGE,4096)];self.c.update(c);self.constructor_frames=[];self.stop_store=c.get('stop_store',False)
  if producer is not None:
   self.u.mem_write(P,decode(producer['final_private_RAM']));self.initial=[];self.resume={'path':PREFIX+'_profiles.json','case':index,**producer['final_private_RAM']};self.image_initial=[]
   for e in producer['final_auxiliary_regions']:self.fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
   for e in producer['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact original map-constructor/component final-global transfer')
  if c['phase']=='create':
   for a,b in[(MZ,bytes(64)),(MZ+0x34,struct.pack('<H',256)),(MA,bytes(16)),(RZ,bytes(64)),(RZ+0x34,struct.pack('<H',256)),(RA,bytes(16))]:self.fixture(a,b)
   for a,b in[(0xfffffe000caec080,struct.pack('<QQ',MZ,MA)),(0xfffffe000caec200,struct.pack('<QQ',RZ,RA)),(0xfffffe000caa4f9c,struct.pack('<I',c['global_flag'])),(COUNTER,struct.pack('<Q',7))]:self.image_fixture(a,b,'Declared map/root zones, constructor flag and counter epoch7; native identities unknown')
   self.entry=0xfffffe000bdc6eac if c['wrapper']else 0xfffffe000bdc6ebc;args=[0,c['minimum'],c['maximum']]if c['wrapper']else[0,c['minimum'],c['maximum'],c['page_shift'],c['flags']]
  elif c['phase']=='copyout':
   self.entry=0xfffffe000bdd1574 if c.get('wrapper',True)else 0xfffffe000bdcb374;args=[KMAP,OUT,COPY]if c.get('wrapper',True)else[KMAP,OUT,COPY,32769,c['consume']]
  elif c['phase']=='lookup':self.entry=0xfffffe000bdc7274;args=[KMAP,c['query'],P+0xa1000]
  else:assert c['phase']=='discard';self.active=c['descriptor_index'];self.entry=0xfffffe000bdc6308;args=[COPY+self.active*0x1000]
  for j in range(31):self.set(j,0)
  for j,x in enumerate(args):self.set(j,x)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.actual_entry_SP=hex(SP)
 def write(self,u,t,a,n,v,d):
  if a==COUNTER:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  arities={0xfffffe000bdc6eac:3,0xfffffe000bdc6ebc:5,0xfffffe000bddd56c:1,0xfffffe000bddf0b0:2,0xfffffe000bddf2c8:5,0xfffffe000bddf4ec:5,0xfffffe000bddfe6c:2,0xfffffe000be2fac0:2,0xfffffe000bddd5dc:2}
  if a in arities:self.constructor_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(arities[a])],'map256_hex':bytes(u.mem_read(KMAP,256)).hex(),'root256_hex':bytes(u.mem_read(ROOTPAGE,256)).hex()if ROOTPAGE in self.pages else None})
  if a==0xfffffe000bd75c64 and self.reg(30)in[0xfffffe000bdc6f14,0xfffffe000bdc6f3c]:
   ptr=KMAP if self.reg(30)==0xfffffe000bdc6f14 else ROOTPAGE;self.ensure(ptr,256);return self.effect(a,'declared_zeroed_map_or_root_allocation',ptr,[(ptr,bytes(256),'declared zeroed 256-byte allocator result')])
  if a==0xfffffe000bd08888:return self.model(a,'declared_map_lock_initialization',0)
  if a==0xfffffe000bcfefc8 and self.c['phase']=='create':return self.effect(a,'declared_auxiliary_store_allocation',EXTSTORE,[(EXTSTORE,bytes(64),'declared zeroed auxiliary store result')])
  if a==0xfffffe000c647f10:
   ptr,src,count=[self.reg(j)for j in range(3)];return self.effect(a,'declared_store_memmove',ptr,[(ptr,bytes(u.mem_read(src,count)),'snapshot source bytes for overlapping move')])
  if a==0xfffffe000bddf0b0 and not self.stop_store:return self.source_or_stop(a)
  if a==0xfffffe000bddd5dc and self.c['phase']=='lookup':return self.source_or_stop(a)
  return super().code(u,a,n,d)
 def source_or_stop(self,a):
  raw=bytes(self.u.mem_read(a,4));ins=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4)and ins.mnemonic=='bti';self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def run(self):
  row=super().run();row.update(map_constructor_frames=self.constructor_frames,root256_hex=bytes(self.u.mem_read(ROOTPAGE,256)).hex()if ROOTPAGE in self.pages else None,map_constructor_counter=int.from_bytes(bytes(self.u.mem_read(COUNTER,8)),'little'));return row
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());seed=json.loads((ROOT/'rpc502_reply_copyin_profiles.json').read_text())['cases'][42];factory=json.loads((ROOT/'kernel_vm_entry_copy_profiles.json').read_text())['cases'][4];rows=[]
 configs=[{'phase':'create','wrapper':True,'minimum':P,'maximum':P+SIZE,'page_shift':14,'flags':0,'global_flag':0},{'phase':'create','wrapper':False,'minimum':P+1,'maximum':P+SIZE-1,'page_shift':12,'flags':4,'global_flag':0},{'phase':'create','wrapper':False,'minimum':P+3,'maximum':P+SIZE-3,'page_shift':14,'flags':3,'global_flag':1},{'phase':'create','wrapper':False,'minimum':P,'maximum':P+SIZE,'page_shift':14,'flags':16,'global_flag':0}]
 for c in configs:
  row=Probe(im,c,src,seed,factory).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':row['boundary'],'visits':len(row['source_visits'])}),flush=True)
 for c in [{'phase':'copyout','resolver_result':None},{'phase':'copyout','resolver_result':3},{'phase':'copyout','resolver_result':0}]:
  row=Probe(im,c,src,seed,factory,rows[0],0).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':row['boundary'],'visits':len(row['source_visits'])}),flush=True)
 for c,parent in [({'phase':'copyout','resolver_result':0,'wrapper':False,'consume':0},0),({'phase':'discard','descriptor_index':0},7),({'phase':'discard','descriptor_index':1},6)]+[({'phase':'lookup','query':q},6)for q in[P+0x30000-1,P+0x30000,P+0x30000+32768,P+0x3c000-1,P+0x3c000]]+[({'phase':'lookup','query':q},8)for q in[P+0x30000,P+0x3c000]]:
  row=Probe(im,c,src,seed,factory,rows[parent],parent).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':row['boundary'],'visits':len(row['source_visits'])}),flush=True)
 deps=[PREFIX+'_source.json','kernel_vm_entry_copy_profiles.json','rpc502_reply_copyin_profiles.json','probe_kernel_type2_copyout.py','probe_kernel_vm_entry_copy.py','probe_kernel_vm_range_cursor.py','probe_rpc502_vm_handoff.py','probe_rpc502_reply_copyin.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
