#!/usr/bin/env python3
"""Original sample-size caller envelope, constant bank identities and records.

Read-only original KC/normalized bytes. O(B+I+256R+chain work) time and source
space, for input bytes B, instructions I and selected bank rules R.
"""
import hashlib,json,struct,re
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,selected,qword
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
ENTRY=0xfffffe000a6247a4
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def span(k,a,z):
 raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a)
 return {'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]}
def builders(k,fp):
 out=[]
 for name,parent,fragment,end,prefix_end,fields,rule in[
  ('first',0xfffffe000a635208,0xfffffe000a64b284,0xfffffe000a64b5b4,0xfffffe000a635470,[0x738,0xa40,0xa48,0xa60,0x3a8],selected(0xfffffe0007949dd0,0xfffffe000792fbc0,0x73,0xf1c)),
  ('second',0xfffffe000a6890dc,0xfffffe000a68f448,0xfffffe000a68f770,0xfffffe000a689360,[0x2d8,0x3f8,0x400,0x440],selected(0xfffffe0007949ed0,0xfffffe000792fec0,0x32,0xe6a))]:
  f=function(k,fp,parent);raw=bytes.fromhex(f['bytes_hex']);assert IMAGE.read(parent,len(raw))==raw;stores=[]
  for ins in f['instructions']:
   if ins['mnemonic']not in['str','stur','stp']:continue
   m=re.search(r'\[sp(?:, #(-?0x[0-9a-f]+|-?\d+))?\]',ins['operands'])
   if not m:continue
   off=int(m[1]or'0',0);width=(8 if ins['operands'].startswith('x')else 4)*(2 if ins['mnemonic']=='stp'else 1);overlap=[v for v in fields if off<=v<off+width]
   if overlap:stores.append(dict(ins,overlapping_offsets=overlap))
  out.append({'name':name,'parent_compiler_start':f['start'],'parent_compiler_end':f['end'],'parent_sha256':f['sha256'],'parent_instructions':len(f['instructions']),'fragment':span(k,fragment,end),'entry_prefix':span(k,parent,prefix_end),'call_rule':rule,'literal_SP_store_census':stores,'frame_reaching_definitions_proved':False,'task_semantic_origin_proved':False})
 return out
def main():
 k=Kernel();fp=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');f=function(k,fp,ENTRY);assert IMAGE.read(ENTRY,int(f['end'],16)-ENTRY).hex()==f['bytes_hex']
 banks={'A':(0xfffffe0007949dd0,0xfffffe000792fbc0),'B':(0xfffffe0007949fd0,0xfffffe000792ffc0),'C':(0xfffffe0007949ed0,0xfffffe000792fec0),'D':(0xfffffe000792fcc0,0xfffffe00079391f0),'E':(0xfffffe0007941f60,0xfffffe000794a0d0)}
 specs=[('global1','A',0x16,-0x7c,POOL,0),('global2_plus4','A',0xd8,-4,POOL,0),('table','A',0x73,-0x14,POOL,-12),('bounds','B',0x37,0xee7,TABLE,0),('create','B',0x37,0xf65,TABLE,0),('prepare','C',0x92,0xe8e,TABLE,0),('complete','C',0x32,0xeaf,TABLE,0),('release','A',0x3e,0xf29,TABLE,0),('initialize','E',0x6d,0xf2d,TABLE,0),('samples_create','C',0x32,0xeb2,TABLE,0),('samples_prepare','D',0x47,0xf42,TABLE,0)]
 rules=[]
 for label,fam,key,add,base,bias in specs:
  row=selected(*banks[fam],key,add,base=base,bias=bias);row.update(label=label,base=hex(base),left256_hex=IMAGE.read(banks[fam][0],256).hex(),right256_hex=IMAGE.read(banks[fam][1],256).hex(),original_pointer=pointer(k,int(row['slot'],16)));rules.append(row)
 rules_by={r['label']:r for r in rules};assert rules_by['bounds']['target']=='0xfffffe000a687ecc';assert rules_by['create']['target']=='0xfffffe000a509948';assert rules_by['prepare']['target']=='0xfffffe000a5099b8';assert rules_by['complete']['target']=='0xfffffe000a509c08';assert rules_by['release']['target']=='0xfffffe000a509bd4'
 routes=[]
 for label,index in [('create_zero',0x507),('create_nonzero',0x50b),('prepare_zero',0x92a),('prepare_nonzero',0x739)]:
  slot=TABLE+index*8;p=pointer(k,slot);assert int(p['target'],16)==qword(slot);routes.append({'label':label,'index':hex(index),'slot':hex(slot),'original_pointer':p,'target':p['target']})
 raw=IMAGE.read(0xfffffe000a687ecc,20);assert k.read(0xfffffe000a687ecc,20)==raw
 record=[{'offset':off,'width_bytes':w,'role':role}for off,w,role in[(0,8,'object operand, plus 0x140 for unsigned guard'),(8,4,'encoded output status word on inspected paths'),(0x10,8,'encoded samples byte length64'),(0x18,8,'sample-size address64'),(0x20,8,'secondary record pointer after successful preparation'),(0x28,8,'saved pointer, later role unresolved'),(0x30,8,'saved pointer, later role unresolved'),(0x38,8,'task64 argument for both descriptor groups'),(0x40,4,'encoded selector32'),(0x48,8,'guard limit64'),(0x50,4,'encoded element-count word32'),(0x58,8,'samples address64')]]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','sample_descriptor_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'function':f,'entry_pointer':pointer(k,0xfffffe000847aa38),'record_fields':record,'minimum_full_inspected_prefix_extent_bytes':0x60,'bank_rules':rules,'selected_routes':routes,'bounds_helper':{'start':'0xfffffe000a687ecc','bytes_hex':raw.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,0xfffffe000a687ecc)]},'count_contract':{'key64':'(record64 XOR 0x0f6f4af997099bc0) * 0xef54ff65 mod 2^64','key32':'low32(key64)','selector32':'word40 + key32 mod 2^32','element_count32':'word50 - key32 + 0x8899d805 mod 2^32','length64':'zero_extend64(element_count32) * 4','max_length_bytes':0x3fffffffc,'samples_length64':'word10 + key64 + 0xecb67a32353f2154 mod 2^64','output_word8':'local status32 XOR 0x31ae0066 on inspected return paths; consumer not proved'},'source_calls':{'bounds':'0xfffffe000a6249a4','create':'0xfffffe000a624b44','prepare':'0xfffffe000a624be4','release_after_prepare_error':'0xfffffe000a625840','complete':'0xfffffe000a6257e8','initialize':'0xfffffe000a6250c8','samples_create':'0xfffffe000a625190','samples_prepare':'0xfffffe000a625254','unresolved_memory_helper':'0xfffffe000a6252dc'},'native_target_executed':False,'record_producer_proved':False,'complete_lifecycle_proved':False,'full_goal_complete':False}
 out['builder_contexts']=builders(k,fp)
 (ROOT/'sample_caller_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'function_bytes':(int(f['end'],16)-ENTRY),'rules':len(rules),'routes':len(routes),'record_fields':len(record),'builder_contexts':len(out['builder_contexts'])}),flush=True)
if __name__=='__main__':main()
