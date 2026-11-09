#!/usr/bin/env python3
"""Exact original nominal-vtable registration endpoint after provider start gates.
O(image bytes+symbols), O(image bytes); no native registration or PAC execution.
"""
import hashlib,json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_aes_handoff import definitions
from recover_kext_constructor_request import sha
P='kext_provider_initialize'
def main():
 im=Image();names=['__ZTV30com_apple_driver_FairPlayIOKit','__ZTV9IOService'];defs=definitions(im.k,names);rows=[]
 for name in names:
  assert len(defs[name])==1;base=int(defs[name][0]['address'],16);pointer=im.pointer(base+16+0x5e0);assert pointer['target']=='0xfffffe000c4d8394'and pointer['auth']==1 and pointer['diversity']=='0x7d59'and pointer['address_diversity']==1;rows.append({'vtable_definition':defs[name][0],'vtable_name':name,'offset_from_vptr':1504,'pointer':pointer,'exact_symbols':im.k.symbols([int(pointer['target'],16)])[pointer['target']]})
 a=0xfffffe000a50ab58;raw=im.k.read(a,0x8c);instructions=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)];direct=[r for r in instructions if r['mnemonic']=='bl'];assert[(r['ea'],r['operands'])for r in direct]==[('0xfffffe000a50ab90','#0xfffffe000a5053f4'),('0xfffffe000a50ab98','#0xfffffe000a5a38cc')];assert any(r['ea']=='0xfffffe000a50abd8'and r['mnemonic']=='blraa'and r['operands']=='x8, x16'for r in instructions)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['recover_kext_aes_handoff.py','kernel_vm_mig_tools.py',P+'_source.json']},'kernel_sha256':im.k.sha256,'nominal_vtable_slots':rows,'caller':{'start':hex(a),'end':hex(a+len(raw)),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':instructions},'native_target_executed':False,'native_registration_executed':False,'runtime_vptr_identity_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_registration.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'exact_vtable_slots':len(rows),'target':'IOService::registerService(unsigned int)','native_registration_executed':False}),flush=True)
if __name__=='__main__':main()
