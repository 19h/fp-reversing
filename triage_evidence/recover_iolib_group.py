#!/usr/bin/env python3
"""IOKit group construction/publication, startup order and bounded references.

Read-only original KC and source metadata. O(B+I+N) time/source space plus
bounded 12-instruction windows. No native startup/lock/registry/heap operation.
"""
import bisect,hashlib,json,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.arm64 import ARM64_OP_MEM,ARM64_OP_REG
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE
GROUP=0xfffffe000cb524a8;CELL=0xfffffe000cb52628;INIT=0xfffffe000c4b91a8
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def reference_census(k):
 s=next(v for v in k.kernel['segments']if v['name']=='__TEXT_EXEC');raw=k.read(s['address'],s['file_size']);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;rows=[];pages=0;callers=[]
 for j,(word,)in enumerate(struct.iter_unpack('<I',raw[:len(raw)//4*4])):
  a=s['address']+j*4
  if word&0x7c000000==0x14000000:
   d=word&0x3ffffff;d=d-(1<<26)if d&(1<<25)else d
   if(a+d*4)&((1<<64)-1)==INIT:callers.append({'pc':hex(a),'mnemonic':'bl'if word&0x80000000 else'b','bytes_hex':raw[j*4:j*4+4].hex()})
  if word&0x9f000000!=0x90000000:continue
  imm=((word>>29)&3)|(((word>>5)&0x7ffff)<<2);imm=imm-(1<<21)if imm&(1<<20)else imm;page=((a&~4095)+(imm<<12))&((1<<64)-1)
  if page!=CELL&~4095:continue
  pages+=1;reg='x'+str(word&31)
  for i in cs.disasm(k.read(a+4,min(44,s['address']+s['file_size']-a-4)),a+4):
   if i.mnemonic.startswith(('ldr','str','ldur','stur','ldp','stp')):
    mem=next((o.mem for o in i.operands if o.type==ARM64_OP_MEM),None)
    if mem is not None and i.reg_name(mem.base)==reg and not mem.index and not i.writeback:
     name=i.reg_name(i.operands[0].reg);width=16 if name.startswith('q')else 8 if name.startswith(('x','d'))else 4
     if i.mnemonic.endswith('b'):width=1
     elif i.mnemonic.endswith('h'):width=2
     if i.mnemonic in['stp','ldp']:width*=2
     address=page+mem.disp
     if address<CELL+8 and CELL<address+width:
      ix=bisect.bisect_right(k.starts,i.address)-1;rows.append({'ADRP_PC':hex(a),'memory_PC':hex(i.address),'base_register':reg,'address':hex(address),'width_bytes':width,'direction':'write'if i.mnemonic.startswith('st')else'read','mnemonic':i.mnemonic,'operands':i.op_str,'bytes_hex':k.read(i.address,4).hex(),'compiler_start':hex(k.starts[ix]),'compiler_end':hex(k.starts[ix+1])})
   if any(i.group(g)for g in[CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET]):break
   if any(i.reg_name(r)==reg for r in i.regs_access()[1]):break
 assert len({r['memory_PC']for r in rows})==len(rows)
 return {'scope':'Kernel __TEXT_EXEC aligned words; ADRP to cell page followed by at most 11 instructions, same unchanged base, immediate memory overlap, no indexed/writeback form, stop at control transfer. Other aliases/forms/segments are excluded.','segment_start':hex(s['address']),'segment_bytes':s['file_size'],'words_scanned':len(raw)//4,'page_ADRP_candidates':pages,'references':rows,'direct_IOLibInit_callers':callers}
def main():
 k=Kernel();addresses=[INIT,0xfffffe000bd037e0,0xfffffe000be3e3c4,0xfffffe000bc9db70,0xfffffe000c647f10,0xfffffe000bceb1d0,0xfffffe000bdc1800,0xfffffe000bddc5bc,0xfffffe000bd03ec4,0xfffffe000c4bb6e4,0xfffffe000c4bb780,0xfffffe000c4bcc70];fs=[k.function(a)for a in addresses];census=reference_census(k);assert[(r['memory_PC'],r['mnemonic'])for r in census['references']if r['direction']=='write']==[('0xfffffe000c4b91e8','str')];assert[c['pc']for c in census['direct_IOLibInit_callers']]==['0xfffffe000c4bcca8']
 data=[]
 for label,a,n in[('group_storage',GROUP,0x148),('group_cell',CELL,8),('ready_byte',0xfffffe000cba36b0,1),('default_group_flags',0xfffffe0007e635c8,4),('registration_phase_word',0xfffffe0007f8b5f0,4),('name',0xfffffe00070da7ab,6),('setup_input_pointer',0xfffffe0007f860a8,8),('setup_input_vector',0xfffffe0007f36928,16)]:data.append({'label':label,'address':hex(a),'bytes_hex':k.read(a,n).hex()})
 syms=k.symbols(addresses+[0xfffffe000c47c364,CELL,GROUP,0xfffffe0007f8b5f0]);assert '_IOLibInit'in[x['name']for x in syms[hex(INIT)]]and'_OSlibkernInit'in[x['name']for x in syms['0xfffffe000c47c364']]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','rw_lifecycle_contracts.json','sample_lock_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'exact_symbols':syms,'data':data,'reference_census':census,'constructor_partial_layout':{'minimum_written_extent_bytes':328,'initial_word0':1,'name_offset':24,'name_capacity_bytes':64,'header_word4':'low32(registry_return) OR flags32','flag16_counter_offsets':[0x60,0x78,0xa8,0xc0,0xf0,0x108,0x120,0x138],'flag17_counter_offsets':[0x90,0xd8],'native_sizeof_proved':False},'model_boundaries':{'registry':'0xfffffe000bd0392c','first_setup':'0xfffffe000c4b9210','second_setup':'0xfffffe000c4b9224','mutex_allocation':'0xfffffe000c4b9238','before_registry_lock_path':'0xfffffe000bd03900'},'publication_site':'0xfffffe000c4b91e8','ready_commit_site':'0xfffffe000c4b9254','source_order':['group construction and registration return','group pointer publication','two setup calls','mutex allocation/publication','self-linked list initialization','ready byte = 1'],'native_target_executed':False,'native_startup_proved':False,'cached_FairPlay_lock_publication_proved':False,'full_goal_complete':False};(ROOT/'iolib_group_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'references':len(census['references']),'bounded_writers':1,'page_candidates':census['page_ADRP_candidates'],'direct_callers':len(census['direct_IOLibInit_callers'])}),flush=True)
if __name__=='__main__':main()
