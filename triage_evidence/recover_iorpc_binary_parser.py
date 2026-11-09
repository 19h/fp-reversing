#!/usr/bin/env python3
"""Original binary parser and collection-call closure for valid emitted objects.
O(image+symbols+instructions), O(image+source). No native parser/VM effects.
"""
import json
from collections import deque
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import definitions
P='iorpc_binary_parser'
def main():
 im=Image();k=im.k;out=dict(json.loads((ROOT/'iorpc_ool_serialization_source.json').read_text()));funcs=list(out['functions']);have={int(f['start'],16)for f in funcs};defs=definitions(k,['__ZTVN12OSDictionary9MetaClassE','__ZTV12OSDictionary','__ZTV6OSData','__ZN12OSDictionary10gMetaClassE','__ZN8OSSymbol10gMetaClassE','__ZN8OSString10gMetaClassE','__ZN8OSNumber10gMetaClassE']);slots=[];todo=[0xfffffe000c489b18,0xfffffe000c484334,0xfffffe000bcff0b8,0xfffffe000bcfec48]
 for name,offs in [('__ZTVN12OSDictionary9MetaClassE',[0xa8]),('__ZTV12OSDictionary',[0x1d0,0x1d8,0x1e0,0x1e8,0x1f0,0x1f8,0x200,0x208,0x210,0x218,0x220,0x228,0x230]),('__ZTV6OSData',[0x140,0x148,0x150,0x158])]:
  v=int(defs[name][0]['address'],16)+16
  for off in offs:
   p=im.pointer(v+off);slots.append({'class':name,'offset':off,'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]});todo.append(int(p['target'],16))
 todo=deque(todo)
 while todo:
  a=todo.popleft()
  if a in have:continue
  f=k.function(a,exact=True);f['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(f);have.add(a)
  if a in [0xfffffe000c489b18,0xfffffe000c484334,0xfffffe000bcff0b8,0xfffffe000bcfec48]:continue
  for i in f['instructions']:
   if i['mnemonic']not in['bl','b']or not i['operands'].startswith('#0x'):continue
   t=int(i['operands'][1:],16)
   if not a<=t<int(f['end'],16)and 0xfffffe000c444e00<=t<0xfffffe000c450000:todo.append(t)
 parser=next(f for f in funcs if f['start']=='0xfffffe000c489b18');calls=sorted({int(i['operands'][1:],16)for i in parser['instructions']if i['mnemonic']in['bl','b']and i['operands'].startswith('#0x')and not int(parser['start'],16)<=int(i['operands'][1:],16)<int(parser['end'],16)})
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['iorpc_ool_serialization_source.json','iorpc_ool_serialization_profiles.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},functions=funcs,binary_parser_slots=slots,binary_parser_definitions=defs,binary_parser_direct_calls=k.symbols(calls),native_binary_parser_executed=False,full_goal_complete=False)
 (ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'binary_parser_slots':len(slots),'bindings':[(s['class'],s['offset'],s['pointer']['target'],s['exact_symbols'])for s in slots]}),flush=True)
if __name__=='__main__':main()
