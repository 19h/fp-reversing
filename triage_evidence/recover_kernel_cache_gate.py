#!/usr/bin/env python3
"""Original free-page/reserved-page cache gate, publication and quota writers.
O(image+instruction words+bounded disassembly+source), O(image+source+windows).
ADRP-window inventory does not establish arbitrary indirect writer completeness.
"""
import json,struct
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_OP_MEM
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_cache_gate';GATE=0xfffffe000ca92380;POLICY=0xfffffe000bd7b938;PUBLISH=0xfffffe000c266258;CURSOR=0xfffffe000bd76a6c;FREE=0xfffffe000cb510e0;RESERVED=0xfffffe000cb2a2b8

def va(im,off):
 sg=next(s for s in im.k.root['segments']if s['file_offset']<=off<s['file_offset']+s['file_size']);return sg['address']+off-sg['file_offset']
def cstr(k,a):return k.read(a,256).split(b'\0')[0].decode()
def scan(im):
 k=im.k;cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;hits=[];calls=[];words=0;seen=set();refs={};offset_mentions=[]
 def rn(i,r):return i.reg_name(r).replace('w','x',1)
 for ent in k.entries:
  for sec in ent['sections']:
   key=(sec['address'],sec['size'])
   if key in seen or not sec['flags']&0x80000400:continue
   seen.add(key);raw=k.read(sec['address'],sec['size']&~3);words+=len(raw)//4
   for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
    a=sec['address']+4*j
    if w&0xfc000000==0x94000000:
     imm=w&0x3ffffff;imm-=(imm>>25)<<26;t=(a+(imm<<2))&((1<<64)-1)
     if t in[POLICY,PUBLISH,CURSOR]:calls.append({'entry':ent['name'],'pc':hex(a),'target':hex(t),'bytes_hex':k.read(a,4).hex(),'caller':k.function(a,exact=False)['start']})
    if w&0x9f000000!=0x90000000:continue
    imm=((w>>5)&0x7ffff)<<2|((w>>29)&3);imm-=(imm>>20)<<21;target=((a&~4095)+(imm<<12))&((1<<64)-1)
    if target!=GATE&~4095:continue
    rr=k.read(a,128);ins=list(cs.disasm(rr,a));hits.append({'entry':ent['name'],'pc':hex(a),'bytes_hex':rr.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]});known={}
    for i in ins:
     ops=i.operands
     if '#0x380'in i.op_str:offset_mentions.append({'ADRP':hex(a),'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
     for o in ops:
      if o.type==ARM64_OP_MEM and not o.mem.index and rn(i,o.mem.base)in known and known[rn(i,o.mem.base)]+o.mem.disp==GATE:refs[hex(i.address)]={'pc':hex(i.address),'ADRP':hex(a),'entry':ent['name'],'mnemonic':i.mnemonic,'operands':i.op_str,'bytes_hex':i.bytes.hex(),'function':k.function(i.address,exact=False)['start']}
     result=None
     if i.mnemonic=='adrp':result=(rn(i,ops[0].reg),ops[1].imm&((1<<64)-1))
     elif i.mnemonic=='add'and len(ops)==3 and ops[2].type==ARM64_OP_IMM and rn(i,ops[1].reg)in known:result=(rn(i,ops[0].reg),(known[rn(i,ops[1].reg)]+ops[2].imm)&((1<<64)-1))
     elif i.mnemonic=='mov'and len(ops)==2 and ops[1].type==ARM64_OP_REG and rn(i,ops[1].reg)in known:result=(rn(i,ops[0].reg),known[rn(i,ops[1].reg)])
     for r in i.regs_access()[1]:known.pop(rn(i,r),None)
     if i.mnemonic.startswith('bl'):
      for r in range(19):known.pop('x'+str(r),None)
     if result:known[result[0]]=result[1]
 return {'instruction_words':words,'page_ADRP_hits':hits,'window_bytes':128,'resolved_syntactic_memory_references':list(refs.values()),'raw_offset_mentions':offset_mentions,'direct_calls':calls,'arbitrary_indirect_reference_completeness_established':False}
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_zone_refill_source.json').read_text()));starts=[*[int(f['start'],16)for f in out['functions']],POLICY,PUBLISH,CURSOR,0xfffffe000bd0ae78,0xfffffe000bd0aab4,0xfffffe000bd0ab18];syms=im.k.symbols(starts);funcs=[]
 for a in starts:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];funcs.append(f)
 metadata=[]
 for target in[FREE,RESERVED]:
  matches=[(o,r)for o,r in im.meta.items()if r['target']==hex(target)];assert len(matches)==1;off,row=matches[0];slot=va(im,off);record=slot-24;fields={}
  for label,at in[('argument',slot),('name',slot+16),('handler',slot+24),('format',slot+32)]:fields[label]=im.pointer(at)
  fields['name_text']=cstr(im.k,int(fields['name']['target'],16));fields['format_text']=cstr(im.k,int(fields['format']['target'],16));handler=int(fields['handler']['target'],16);fields['handler_symbols']=im.k.symbols([handler])[hex(handler)]
  if im.k.read(slot+40,8)!=bytes(8):fields['description_pointer']=im.pointer(slot+40);fields['description']=cstr(im.k,int(fields['description_pointer']['target'],16))
  metadata.append({'counter':hex(target),'record_address':hex(record),'bytes80_hex':im.k.read(record,80).hex(),'fields':fields})
 references=[]
 for off,row in im.meta.items():
  if row['target']in[hex(POLICY),hex(PUBLISH),hex(CURSOR),hex(GATE)]:references.append({'pointer':im.pointer(va(im,off)),'container_start':hex(va(im,off)-16),'container64_hex':im.k.read(va(im,off)-16,64).hex()})
 allscan=scan(im);symbols=im.k.symbols([0xfffffe000c2b9748,0xfffffe0007f8c250,0xfffffe000bd5d120]);out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_zone_refill_source.json','kernel_zone_refill_profiles.json','kernel_zone_startup_profiles.json','kernel_vm_mig_tools.py','kext_port_tools.py']},functions=funcs,gate_reference_scan=allscan,counter_metadata=metadata,gate_related_fixup_references=references,publication_and_followup_exact_symbols=symbols,gate_file_byte_hex=im.k.read(GATE,1).hex(),policy_parameter_file_bytes=[{'address':hex(a),'bytes_hex':im.k.read(a,n).hex()}for a,n in[(0xfffffe0007e66e2c,4),(0xfffffe0007e66e30,4),(0xfffffe0007e66e34,4),(0xfffffe000cb115b0,4),(0xfffffe000cb0bc50,4)]],other_zone_self_file_words=[{'identifier':j,'address':hex(0xfffffe000caeb480+192*j),'bytes8_hex':im.k.read(0xfffffe000caeb480+192*j,8).hex()}for j in range(1,40)if j!=24],gate_native_value_observed=False,**{k:False for k in FLAGS});(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'scan_words':allscan['instruction_words'],'page_ADRP_hits':len(allscan['page_ADRP_hits']),'resolved_memory_references':allscan['resolved_syntactic_memory_references'],'direct_calls':allscan['direct_calls'],'counter_metadata':metadata,'fixup_refs':references}),flush=True)
if __name__=='__main__':main()
