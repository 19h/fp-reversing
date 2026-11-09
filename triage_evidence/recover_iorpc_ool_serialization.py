#!/usr/bin/env python3
"""Original SetProperties IORPC producer, binary serializer and OOL interfaces.
O(image+symbols+instructions), O(image+source); no native serialization/VM calls.
"""
import json
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import definitions
P='iorpc_ool_serialization'
def main():
 im=Image();k=im.k;out=dict(json.loads((ROOT/'iorpc_object_conversion_source.json').read_text()));funcs=list(out['functions']);have={int(f['start'],16)for f in funcs};names=['__ZTV11OSSerialize','__ZTV7OSArray','__ZTV12OSDictionary','__ZTV6OSData','__ZTV8OSSymbol','__ZTVN11OSSerialize9MetaClassE','__ZTVN7OSArray9MetaClassE','__ZTVN6OSData9MetaClassE'];defs=definitions(k,names+['__ZN11OSSerialize10gMetaClassE','__ZN7OSArray10gMetaClassE','__ZN6OSData10gMetaClassE','__ZN12OSDictionary10gMetaClassE','__ZN8OSSymbol10gMetaClassE','__ZN8OSString10gMetaClassE']);slots=[];todo=[0xfffffe000c4a41a8,0xfffffe000c4a3290,0xfffffe000c488ca0,0xfffffe000c47d014,0xfffffe000c47d618,0xfffffe000c489088,0xfffffe000c488ed0,0xfffffe000c488964]
 for name,offs in [(names[0],[0x20,0x28,0x38,0x138,0x148,0x150,0x170,0x178,0x198]),(names[1],[0x20,0x28,0x38,0x150,0x1d0,0x1e8,0x1f0,0x1f8,0x200,0x208,0x210,0x218,0x220,0x228,0x230]),(names[2],[0x20,0x28,0x30,0x38,0x48,0x50]),(names[3],[0x20,0x28,0x30,0x38,0x138,0x160,0x188,0x198]),(names[4],[0x20,0x28,0x30,0x38,0x48,0x50,0x150,0x158,0x160,0x168,0x170,0x178,0x180,0x188,0x190,0x198]),*[(n,[0xa8])for n in names[5:]]]:
  v=int(defs[name][0]['address'],16)+16
  for off in offs:
   p=im.pointer(v+off);slots.append({'class':name,'offset':off,'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]});todo.append(int(p['target'],16))
 while todo:
  a=todo.pop(0)
  if a in have:continue
  f=k.function(a,exact=True);f['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(f);have.add(a)
  if a==0xfffffe000c488964:continue
  for i in f['instructions']:
   if i['mnemonic']not in ['bl','b']or not i['operands'].startswith('#0x'):continue
   target=int(i['operands'][1:],16)
   if (0xfffffe000c444e00<=target<0xfffffe000c44d000)or(0xfffffe000c47d000<=target<0xfffffe000c47e000)or target in [0xfffffe000c488ed0,0xfffffe000c489088]or(a==0xfffffe000c489088 and 0xfffffe000c440000<=target<0xfffffe000c490000):
    if not a<=target<int(f['end'],16):todo.append(target)
 for a in [0xfffffe000bdd15a4,0xfffffe000bdcb374,0xfffffe000bdc1ec0,0xfffffe000bdc08e0]:
  if a not in have:f=k.function(a,exact=True);f['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(f);have.add(a)
 wrapper=next(f for f in funcs if f['start']=='0xfffffe000c488964');calls=[int(i['operands'][1:],16)for i in wrapper['instructions']if i['mnemonic']=='bl'];out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['iorpc_object_conversion_source.json','iorpc_object_conversion_profiles.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},functions=funcs,serialization_slots=slots,serialization_definitions=defs,unserialize_wrapper_calls=k.symbols(calls),SetProperties_constants=[{'address':hex(a),'bytes_hex':k.read(a,n).hex()}for a,n in [(0xfffffe000700e938,0x48),(0xfffffe0007010250,16)]],SDK_serialization_headers=[{'path':str(h),'sha256':sha(h),'matched_collection_source_revision_established':False}for h in [Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/libkern/c++')/n for n in ['OSSerialize.h','OSUnserialize.h']]],native_serialized_VM_or_parser_effects_executed=False,kernel_map_file={'address':'0xfffffe0007f860a8','bytes_hex':k.read(0xfffffe0007f860a8,8).hex(),'exact_symbols':k.symbols([0xfffffe0007f860a8])['0xfffffe0007f860a8'],'runtime_identity_established':False},parser_entry_symbols=k.symbols([0xfffffe000c489b18]),binary_magic={'address':'0xfffffe0007045578','bytes_hex':k.read(0xfffffe0007045578,4).hex()},full_goal_complete=False)
 (ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'serialization_slots':len(slots),'parser_calls':out['unserialize_wrapper_calls']}),flush=True)
if __name__=='__main__':main()
