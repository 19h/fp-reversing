#!/usr/bin/env python3
"""Original remote IORPC route, queue/port/header, conversion and transport ABI.
O(image+symbols+instructions), O(image+captured source); no native operations.
"""
import json
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import definitions
P='iorpc_remote'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'platform_iorpc_source.json').read_text());out=dict(old);funcs=list(old['functions']);have={int(f['start'],16)for f in funcs}
 for a in [0xfffffe000c595ac4,0xfffffe000c595bf8,0xfffffe000c596070,0xfffffe000c5962c0,0xfffffe000c5968d8,0xfffffe000c596d64,0xfffffe000c4dedf0,0xfffffe000c58a960,0xfffffe000c4aa748,0xfffffe000bcd00bc,0xfffffe000bcf55dc,0xfffffe000bcf59e0]:
  if a in have:continue
  f=k.function(a,exact=True);f['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(f);have.add(a)
 slots=[]
 for name,base,offs in [('server',0xfffffe0007f56050,[0x20,0x28,0x38,0x5d8]),('queue',0xfffffe0007f354a8,[0x20,0x28,0x38])]:
  for off in offs:
   p=im.pointer(base+off);slots.append({'name':name+'_'+hex(off),'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]})
 anchors=[0xfffffe000cb5b928,0xfffffe000cb52328,0xfffffe000cb5c060,0xfffffe000cb52440,0xfffffe000cb52468,0xfffffe000bcd0448]
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['platform_iorpc_source.json','platform_iorpc_profiles.json','aes_platform_gate_profiles.json','kernel_rpc_transport_contracts.json','rpc700_namespace_contracts.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},functions=funcs,remote_slots=slots,remote_definitions=definitions(k,['__ZTV12IOUserServer','__ZTV15IODispatchQueue']),route_anchors=k.symbols(anchors),remote_header_constant={'address':'0xfffffe000700ead0','bytes_hex':k.read(0xfffffe000700ead0,8).hex()},native_port_objects_observed=False,full_goal_complete=False)
 (ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'remote_slots':len(slots)}),flush=True)
if __name__=='__main__':main()
