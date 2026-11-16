#!/usr/bin/env python3
"""Pinned original serialized-tree API closure. No native firmware claim.
O(collection + fixups + source + data + symbols) time/space.
"""
import bisect,json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_cpu_topology_handoff as B
P='kernel_secure_dt_execution';INIT=0xfffffe000c6622b8;SKIP=0xfffffe000c6625bc;STRCMP=0xfffffe000c66051c
FUNCTIONS=[*B.FUNCTIONS,INIT,SKIP,STRCMP];GLOBALS=0xfffffe0007f8b508;CURSOR=0xfffffe000cba40e8
SCOPE='Original tree-global initializer, path lookup, property reader, child iterator, recursive subtree advance, named-node scan and exact strcmp execute on serialized private fixtures, composed with original CPU enumeration/main/thread setup in selected cases. Boot-option outputs, lower selector0e returns, later CPU-caller epoch, logical PAC/system effects and cache/context helpers remain declared contracts. Authentic firmware contents, native startup, receiver effects and daemon pairing remain unknown.'
FALSE=B.FALSE+['authentic_firmware_tree_established','native_device_tree_execution_established']
def build():
 prior=json.loads(read(ROOT/(B.P+'_checks.json')));assert prior==B.build();im=Image();k=im.k;fs=list(prior['functions'])
 for a in [INIT,SKIP,STRCMP]:
  i=bisect.bisect_left(k.starts,a);assert k.starts[i]==a;b=k.starts[i+1];raw=k.read(a,b-a);ins=list(k.cs.disasm(raw,a));assert len(ins)*4==len(raw)
  fs.append({'start':hex(a),'end':hex(b),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n) for n in [B.P+'_checks.json','recover_kernel_cpu_topology_handoff.py','kernel_native_reader.py','kernel_vm_mig_tools.py']},
  'functions':fs,'strings':prior['strings'],'data_blocks':prior['data_blocks'],'pointer_fixups':prior['pointer_fixups'],'opaque_words':prior['opaque_words'],'exact_symbols':k.symbols([*FUNCTIONS]),
  'verified_counts':{'captured_functions':len(fs),'captured_words':sum(len(f['instructions']) for f in fs),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'matched_prior_functions':len(prior['functions']),'captured_strings':len(prior['strings']),'logical_data_blocks':len(prior['data_blocks']),'original_pointer_fixups':len(prior['pointer_fixups']),'opaque_words_preserved':len(prior['opaque_words'])},
  'conditional_kernel_secure_dt_execution_contract_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']))
