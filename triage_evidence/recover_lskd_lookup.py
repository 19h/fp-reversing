#!/usr/bin/env python3
"""Original table-root producers, file-backed extent, sentinel gates and store inventory.

O(B+I+256R) time and O(B+I) space. Store inventory covers decoded instructions
with register-indexed scale4 addressing only; it is not a writer-lineage proof.
No target or IDB mutation executes.
"""
import hashlib,json,struct,bisect
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM,ARM64_SFT_LSL
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected,qword
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from recover_kext_aes_handoff import starts
TABLE=0xfffffe000ccc7b08;POOL=0xfffffe00084716e0;DISPATCH=0xfffffe000846c420
SPANS=[('vault_table_producer',0xfffffe000a52fc7c,0xfffffe000a52fcb4),('allowed_table_producer',0xfffffe000a55d10c,0xfffffe000a55d15c),('vault_lookup',0xfffffe000a59399c,0xfffffe000a5939ec),('allowed_lookup',0xfffffe000a531144,0xfffffe000a53119c),('vault_secondary_gate',0xfffffe000a56df9c,0xfffffe000a56dffc),('allowed_secondary_gate',0xfffffe000a52dbd8,0xfffffe000a52dc3c),('vault_secondary_zero',0xfffffe000a5410cc,0xfffffe000a541108),('vault_secondary_nonzero_static',0xfffffe000a54b194,0xfffffe000a54b1bc),('allowed_secondary_zero',0xfffffe000a5611b0,0xfffffe000a5611f0),('allowed_secondary_nonzero_static',0xfffffe000a511608,0xfffffe000a51162c),('vault_unknown_kill',0xfffffe000a551f64,0xfffffe000a551f68),('allowed_unknown_kill',0xfffffe000a531164,0xfffffe000a531168)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inventory(k,e):
 s=next(s for s in e['segments']if s['name']=='__TEXT_EXEC');raw=k.read(s['address'],s['file_size']);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;rows=[];decoded=0;unknown=[]
 assert len(raw)%4==0
 for off in range(0,len(raw),4):
  ins=next(cs.disasm(raw[off:off+4],s['address']+off),None)
  if ins is None:unknown.append({'pc':hex(s['address']+off),'bytes_hex':raw[off:off+4].hex()});continue
  decoded+=ins.size
  for op in ins.operands:
   if ins.mnemonic.startswith('st')and op.type==ARM64_OP_MEM and op.mem.index and op.shift.type==ARM64_SFT_LSL and op.shift.value==2:
    rows.append({'pc':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex(),'mnemonic':ins.mnemonic,'operands':ins.op_str,'base_register':ins.reg_name(op.mem.base),'index_register':ins.reg_name(op.mem.index),'scale_bytes':4,'table_alias_established':False})
 assert decoded+len(unknown)*4==len(raw)
 return {'segment_start':hex(s['address']),'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'decoded_instruction_count':decoded//4,'undecoded_aligned_words':unknown,'aligned_words_examined':len(raw)//4,'scope':'Every aligned four-byte word examined independently. Candidates are decoded store instructions with an explicit register index shifted left by2 in this TEXT_EXEC extent. Undecoded words, other addressing, indirect writes, clearing helpers and other images prevent a complete writer claim.','candidates':rows,'complete_table_writer_inventory_proved':False}
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');cat=starts(k,e);ss=[]
 for name,a,z in SPANS:
  s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];j=bisect.bisect_right(cat,a)-1;assert z<=cat[j+1];s.update(label=name,compiler_start=hex(cat[j]),compiler_end=hex(cat[j+1]));ss.append(s)
 rules=[];l=qword(POOL+0x2f8)-4;r=qword(POOL+0x630)-12
 for name,key,add in[('vault_table_root',0x2f,0x4c),('allowed_table_root',0xbb,-0x60)]:
  b=selected(l,r,key,add,base=POOL,bias=-8);assert b['slot']=='0xfffffe0008471af8'and int(b['target'],16)==TABLE;b.update(label=name,base=hex(POOL),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 aliases=[]
 for delta in[-8,-4,0,4,8]:
  for va,off,n in IMAGE.segments:
   data=IMAGE.data[off:off+n];needle=struct.pack('<Q',TABLE+delta);at=data.find(needle)
   while at>=0:aliases.append({'bias_from_table_bytes':delta,'pointer':pointer(k,va+at)});at=data.find(needle,at+1)
 table=k.read(TABLE,4096);assert table==IMAGE.read(TABLE,4096)==bytes(4096)
 data=next(s for s in e['segments']if s['name']=='__DATA');assert data['address']<=TABLE<TABLE+4096<=data['address']+data['file_size']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','recover_carrier_control.py','recover_kext_aes_handoff.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'spans':ss,'table':{'address':hex(TABLE),'entry_width_bytes':4,'indexed_entries':1024,'indexed_extent_bytes':4096,'original4096_hex':table.hex(),'sha256':hashlib.sha256(table).hexdigest(),'file_backed':True,'allocation_object_extent_proved':False,'native_runtime_contents_known':False,'producer_update_lifetime_known':False,'data_segment':data},'bank_rules':rules,'bank_input_slots':[pointer(k,POOL+0x2f8),pointer(k,POOL+0x630)],'bounded_pointer_alias_deltas':[-8,-4,0,4,8],'bounded_pointer_aliases':aliases,'secondary_dispatch_slots':[pointer(k,DISPATCH+ix*8)for ix in[0x53e,0x54a,0x297,0x28b]],'indexed_store_inventory':inventory(k,e),'exact_symbols':k.symbols([TABLE,TABLE+8,0xfffffe000ccc78d0]),'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'lskd_lookup_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(ss),'root_banks':2,'table_bytes':4096,'indexed_store_candidates':len(out['indexed_store_inventory']['candidates'])}),flush=True)
if __name__=='__main__':main()
