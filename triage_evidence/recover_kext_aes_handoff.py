#!/usr/bin/env python3
"""Original kext/provider handoff, command-carrier and caller-candidate evidence.

Read-only source/fixup/SDK analysis; no provider/key/API operation executes.
O(B + N + I + selected-chain work) time/space for bytes, symbols and instructions.
"""
import bisect,hashlib,json,struct,subprocess
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,qword,TABLE,POOL,selected
from recover_kext_cold_init import pointer
from resolve_kernel_collection_interfaces import commands,string
SDK=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk');HEAD=SDK/'System/Library/Frameworks/Kernel.framework/Headers'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def starts(k,e):
 base=next(s['address']for s in e['segments']if s['name']=='__TEXT');out=[]
 for at,cmd,sz in commands(k.data,e['header_offset']):
  if cmd!=0x26:continue
  off,n=struct.unpack_from('<II',k.data,at+8);p=off;v=base
  while p<off+n:
   delta=shift=0
   while True:
    byte=k.data[p];p+=1;delta|=(byte&127)<<shift;shift+=7;assert shift<70
    if byte<128:break
   if not delta:break
   v+=delta;out.append(v)
 return out
def function(k,e,a):
 catalog=starts(k,e);i=catalog.index(a);z=catalog[i+1];raw=k.read(a,z-a);ins=list(CS.disasm(raw,a));assert sum(v.size for v in ins)==len(raw)
 return {'entry':e['name'],'entry_uuid':e['uuid'],'function_starts_count':len(catalog),'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(x.address),'mnemonic':x.mnemonic,'operands':x.op_str}for x in ins]}
def definitions(k,wanted):
 out={n:[]for n in wanted}
 for e in k.entries:
  if 'symtab'not in e:continue
  so,n,st,ss=e['symtab']
  for j in range(n):
   sx,ty,se,ds,v=struct.unpack_from('<IBBHQ',k.data,so+j*16)
   if not v or not sx or sx>=ss:continue
   name=string(k.data,st+sx)
   if name in out:out[name].append({'address':hex(v),'entry':e['name'],'n_type':ty,'n_section':se})
 return out
def sdk_command():return ['clang++','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-I',str(HEAD),'-DKERNEL','-std=c++17','-O2','-S',str(ROOT/'kext_aes_handoff_sdk_probe.cpp'),'-o',str(ROOT/'kext_aes_handoff_sdk_probe.s')]
def references():
 wanted={0xfffffe000a5081b0,0xfffffe000a5083d8,0xfffffe000a508484,0xfffffe000a508534,0xfffffe000a5085e0};direct=[];words=[];ed=[];stats=[]
 for at,cmd,size in commands(IMAGE.data,0):
  if cmd!=0x19:continue
  name=IMAGE.data[at+8:at+24].split(b'\0')[0].decode();va,vm,off,n=struct.unpack_from('<4Q',IMAGE.data,at+24);raw=IMAGE.data[off:off+n];stats.append({'name':name,'start':hex(va),'file_size':n,'u64_words':n//8})
  if name=='__TEXT_EXEC':
   for i,(w,)in enumerate(struct.iter_unpack('<I',raw[:len(raw)//4*4])):
    a=va+i*4
    if w&0x7c000000==0x14000000:
     d=w&0x3ffffff;d=(d-(1<<26)if d&(1<<25)else d)*4;t=(a+d)&((1<<64)-1)
     if t in wanted:direct.append({'pc':hex(a),'target':hex(t),'mnemonic':'bl'if w&0x80000000 else'b','bytes_hex':raw[i*4:i*4+4].hex()})
    if w&0xffe0001f==0xd2800011 and(w>>5)&0xffff==0xed6d:ed.append({'pc':hex(a),'bytes_hex':raw[i*4:i*4+4].hex(),'following_bytes_hex':raw[i*4+4:i*4+8].hex()})
  for i,(v,)in enumerate(struct.iter_unpack('<Q',raw[:len(raw)//8*8])):
   if v in wanted:words.append({'slot':hex(va+i*8),'target':hex(v),'segment':name,'classification':'metadata_word'if name=='__LINKEDIT'else'raw_pointer_candidate'})
 return {'segments':stats,'direct_text_branches':direct,'aligned_u64_matches':words,'ed6d_call_modifier_candidates':ed,'direct_text_scan_words':next(s['file_size']//4 for s in stats if s['name']=='__TEXT_EXEC'),'scope':'Aligned direct B/BL in original text; exact aligned qwords in file-backed segments; metadata matches and indirect candidates are not caller proof.'}
def main():
 k=Kernel();fp=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');crypto=next(e for e in k.entries if e['name']=='com.apple.iokit.IOCryptoAcceleratorFamily');names=['__ZTV16IOAESAccelerator','__ZTV24AppleS8000AESAccelerator','__ZTV13IOCommandPool','__ZTV13IOCommandGate'];defs=definitions(k,names);slots=[]
 for name,offs,kind in[(names[0],[0x890,0x8a0,0x8b8,0x8d0,0x8d8],'aes'),(names[1],[0x890],'candidate_hardware'),(names[2],[0x148,0x150],'command_pool'),(names[3],[0x1e8,0x200,0x208],'command_gate')]:
  assert len(defs[name])==1;vt=int(defs[name][0]['address'],16)
  for off in offs:p=pointer(k,vt+16+off);p.update(vtable_symbol=name,vtable_symbol_address=hex(vt),offset_from_vptr=off,kind=kind);slots.append(p)
 for off in[0x208,0x218,0x220,0x28]:p=pointer(k,0xfffffe0007f85d80+off);p.update(vtable_symbol='__ZTV24IOBufferMemoryDescriptor',vtable_symbol_address='0xfffffe0007f85d70',offset_from_vptr=off,kind='buffer');slots.append(p)
 refs=references();catalog=starts(k,fp)
 for row in refs['ed6d_call_modifier_candidates']:
  ix=bisect.bisect_right(catalog,int(row['pc'],16))-1;row['enclosing_compiler_start']=hex(catalog[ix]);row['enclosing_compiler_end']=hex(catalog[ix+1]);row['indirect_target_resolved']=False
 tagged=[];raw=k.read(0xfffffe0008470000,0xc000)
 for i,(w,)in enumerate(struct.iter_unpack('<Q',raw)):
  if w>>63 and(w>>32)&0xffff==0xed6d:tagged.append(pointer(k,0xfffffe0008470000+i*8))
 addresses=[int(p['target'],16)for p in slots+tagged]+[0xfffffe000c526570];symbols=k.symbols(addresses)
 for p in slots+tagged:p['exact_symbols']=symbols[p['target']]
 fpa=[0xfffffe000a5081b0,0xfffffe000a5083d8,0xfffffe000a508484,0xfffffe000a508534,0xfffffe000a508c78,0xfffffe000a62259c];ca=[0xfffffe000abff358,0xfffffe000abfd2d8,0xfffffe000abfd598,0xfffffe000abfc450,0xfffffe000abfd2c0,0xfffffe000abfcb1c,0xfffffe000abfd4bc];funcs=[function(k,fp,a)for a in fpa]+[function(k,crypto,a)for a in ca];kernel=[k.function(a)for a in[0xfffffe000c526570,0xfffffe000c5361d4,0xfffffe000c51e408,0xfffffe000c51ff48]]
 for r in funcs[:len(fpa)]:assert IMAGE.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']
 r=subprocess.run(sdk_command(),capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr);assembly=(ROOT/'kext_aes_handoff_sdk_probe.s').read_text();assert '520'in assembly and'64512'in assembly,assembly
 base=selected(0xfffffe0007949fd0,0xfffffe000792ffc0,0xac,0x2d,base=POOL,bias=-12);assert int(base['target'],16)==TABLE
 checks=[base,selected(qword(POOL+0x840),qword(POOL+0xbb8),0xb4,0xeb3,base=TABLE),selected(qword(POOL+0xb70),qword(POOL+0xa10),0x32,0xe88,base=TABLE)]
 for row in checks:row['left256_hex']=IMAGE.read(int(row['left'],16),256).hex();row['right256_hex']=IMAGE.read(int(row['right'],16),256).hex()
 assert checks[1]['target']=='0xfffffe000a687ecc'and checks[2]['target']=='0xfffffe000a5085e0'
 helper=IMAGE.read(0xfffffe000a687ecc,20);cp=Path(str(SOURCE)+'.c');excerpt=''.join(cp.read_text().splitlines(keepends=True)[189216:189240]);caller={'function_start':'0xfffffe000a62259c','bounds_assert_call':'0xfffffe000a62276c','cleanup_call':'0xfffffe000a6227b4','cleanup_slot':'0xfffffe000847ab28','resolved_target':'0xfffffe000a5085e0','bank_identities':checks,'assertion_helper':{'start':'0xfffffe000a687ecc','end':'0xfffffe000a687ee0','bytes_hex':helper.hex(),'instructions':[{'ea':hex(x.address),'mnemonic':x.mnemonic,'operands':x.op_str}for x in CS.disasm(helper,0xfffffe000a687ecc)]},'associated_C_excerpt':{'path':str(cp),'sha256':sha(cp),'line_start':189217,'line_end':189240,'text':excerpt},'native_reachability_proved':False,'all_cleanup_callers_resolved':False}
 for row in refs['ed6d_call_modifier_candidates']:
  if row['pc']=='0xfffffe000a6227b0':row.update(indirect_target_resolved=True,resolved_target='0xfffffe000a5085e0',resolution='three exhaustive byte-bank identities and source-preserved table base')
 binding={'slot':'0xfffffe000847c430','target':hex(qword(0xfffffe000847c430)),'exact_symbols':symbols[hex(qword(0xfffffe000847c430))]};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'fileset_function_counts':{fp['name']:len(starts(k,fp)),crypto['name']:len(starts(k,crypto))},'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','resolve_kernel_collection_interfaces.py','kext_buffer_contracts.json','kext_aes_handoff_sdk_probe.cpp']},'functions':funcs,'kernel_functions':kernel,'nominal_slots':slots,'exact_definitions':defs,'withBytes_binding':binding,'reference_scan':refs,'tagged_ed6d_slots':tagged,'tagged_scan_range':['0xfffffe0008470000','0xfffffe000847c000'],'one_resolved_cleanup_caller':caller,'SDK_probe':{'command':sdk_command(),'compile_exit':r.returncode,'stderr':r.stderr,'assembly_path':'kext_aes_handoff_sdk_probe.s','assembly_sha256':sha(ROOT/'kext_aes_handoff_sdk_probe.s'),'primary_headers':[{'path':str(HEAD/'IOKit'/n),'sha256':sha(HEAD/'IOKit'/n)}for n in['IOMemoryDescriptor.h','IOBufferMemoryDescriptor.h']]},'native_target_executed':False,'key_data_contents_recovered':False,'one_cleanup_caller_resolved':True,'all_cleanup_callers_resolved':False,'full_goal_complete':False};(ROOT/'kext_aes_handoff_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'fileset_functions':len(funcs),'kernel_functions':len(kernel),'nominal_slots':len(slots),'direct_text_refs':len(refs['direct_text_branches']),'tagged_ed6d_slots':len(tagged),'SDK_compile_exit':r.returncode}),flush=True)
if __name__=='__main__':main()
