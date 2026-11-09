#!/usr/bin/env python3
"""Original two-gate attachment, maintenance/list lifecycle and instrumentation.
O(image+symbols+instructions), O(image+captured source); no target operations.
"""
import json
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
P='workloop_gate_attachment'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'aes_command_gate_source.json').read_text());funcs=list(old['functions']);have={int(r['start'],16)for r in funcs}
 new=[0xfffffe000c51a38c,0xfffffe000c51ae9c,0xfffffe000c51a604,0xfffffe000c51a1fc,0xfffffe000c51e844,0xfffffe000c51be64,0xfffffe000c51be4c,0xfffffe000c51be58,0xfffffe000c51bd64,0xfffffe000c51beb8,0xfffffe000c51e744,0xfffffe000c57b280,0xfffffe000c57b468,0xfffffe000c57b898,0xfffffe000c57b9a4]
 for a in new:
  if a not in have:r=k.function(a,exact=True);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r);have.add(a)
 slots=[]
 for name,a in [('loop_inGate',0xfffffe0007f3f638+0x158),('loop_maintenance',0xfffffe0007f3f638+0x138),('loop_remove',0xfffffe0007f3f638+0x168),('gate_setWorkLoop',0xfffffe0007f3fbb0+0x148),('gate_getWorkLoop',0xfffffe0007f3fbb0+0x188),('gate_setNext',0xfffffe0007f3fbb0+0x150),('gate_getNext',0xfffffe0007f3fbb0+0x158),('gate_checkForWork',0xfffffe0007f3fbb0+0x140),('gate_disable',0xfffffe0007f3fbb0+0x178),('gate_retain',0xfffffe0007f3fbb0+0x20),('gate_release',0xfffffe0007f3fbb0+0x28),('gate_metaclass_alloc',0xfffffe0007f3fe28+0xa8)]:
  ptr=im.pointer(a);slots.append({'name':name,'pointer':ptr,'exact_symbols':k.symbols([int(ptr['target'],16)])[ptr['target']]})
 assert next(s for s in slots if s['name']=='loop_remove')['pointer']['target']=='0xfffffe000c51a1fc'
 strings=[]
 for a in [0xfffffe00070e0b86,0xfffffe00070e0aaf,0xfffffe00070e0bbc]:
  b=k.read(a,180).split(b'\0')[0];strings.append({'address':hex(a),'bytes_hex':b.hex(),'text':b.decode()})
 head=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/IOKit');headers=[]
 for name in ['IOWorkLoop.h','IOCommandGate.h']:
  q=head/name;t=q.read_text();headers.append({'path':str(q),'sha256':sha(q)})
  if name=='IOWorkLoop.h':assert 'virtual IOReturn removeEventSource(IOEventSource *toRemove);'in t and 'virtual IOReturn addEventSource(IOEventSource *newEvent);'in t
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['aes_command_gate_source.json','aes_command_gate_profiles.json','kernel_vm_mig_tools.py','workloop_gate_attachment_prior_manifest.json']},'kernel_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'functions':funcs,'additional_slots':slots,'diagnostic_role_strings':strings,'feature_flag':{'address':'0xfffffe000cb5b6e0','file_byte_hex':k.read(0xfffffe000cb5b6e0,1).hex(),'exact_symbols':k.symbols([0xfffffe000cb5b6e0])['0xfffffe000cb5b6e0'],'runtime_value_established':False},'gate_metaclass':{'object':'0xfffffe000cb52db8','file_vptr_hex':k.read(0xfffffe000cb52db8,8).hex(),'nominal_vptr':'0xfffffe0007f3fe28','vtable_symbols':k.symbols([0xfffffe0007f3fe18])['0xfffffe0007f3fe18'],'runtime_identity_established':False},'SDK_headers':headers,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(r['instructions'])for r in funcs),'additional_slots':len(slots)}),flush=True)
if __name__=='__main__':main()
