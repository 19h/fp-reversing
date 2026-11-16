#!/usr/bin/env python3
"""Pinned original boot-option parser closure and literal data.
O(collection + fixups + source + data + symbols) time/space. No native boot.
"""
import bisect,json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_kernel_boot_header_handoff import logical
import recover_kernel_secure_dt_execution as B
P='kernel_boot_option_execution';PARSE=B.B.PARSE;NUMBER=0xfffffe000c5e4d20;FLAG=0xfffffe000c5e4ca8;SPACE=0xfffffe000c5e4f50;STRLEN=0xfffffe000bc9db70;ONE=0xfffffe00070eb5dc;LITERAL=0xfffffe000bc9daa0
FUNCTIONS=[*B.FUNCTIONS,STRLEN,FLAG,NUMBER,SPACE]
SCOPE='Original boot-option scanner, numeric decoder, delimiter callback, flag-width writer and strlen execute on bounded well-formed private option buffers. Original serialized-tree APIs, CPU enumeration, post-enumeration helper and thread setup compose in selected cases. Logical callback-pointer PAC/authenticated calls, tree-initializer/main and later CPU-caller epochs, selector0e/cache/context returns, authentic boot inputs and daemon pairing remain conditional or unknown.'
FALSE=B.FALSE+['authentic_boot_options_established','native_boot_option_execution_established']
def build():
 prior=json.loads(read(ROOT/(B.P+'_checks.json')));assert prior==B.build();im=Image();k=im.k;fs=list(prior['functions'])
 for a in [STRLEN,FLAG,NUMBER,SPACE]:
  j=bisect.bisect_left(k.starts,a);assert k.starts[j]==a;b=k.starts[j+1];raw=k.read(a,b-a);ins=list(k.cs.disasm(raw,a));assert len(ins)*4==len(raw)
  fs.append({'start':hex(a),'end':hex(b),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
 strings=prior['strings']+[{'address':hex(ONE),'bytes_hex':k.read(ONE,2).hex(),'text':k.read(ONE,1).decode('ascii')}]
 blocks=prior['data_blocks']+[{'address':hex(LITERAL),'size_bytes':32,'raw_hex':k.read(LITERAL,32).hex(),'logical_hex':logical(im,LITERAL,32).hex()}]
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n) for n in [B.P+'_checks.json','recover_kernel_secure_dt_execution.py','kernel_native_reader.py','kernel_vm_mig_tools.py']},
  'functions':fs,'strings':strings,'data_blocks':blocks,'pointer_fixups':prior['pointer_fixups'],'opaque_words':prior['opaque_words'],'exact_symbols':k.symbols([*FUNCTIONS]),
  'verified_counts':{'captured_functions':len(fs),'captured_words':sum(len(f['instructions']) for f in fs),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'matched_prior_functions':len(prior['functions']),'captured_strings':len(strings),'logical_data_blocks':len(blocks),'original_pointer_fixups':len(prior['pointer_fixups']),'opaque_words_preserved':len(prior['opaque_words'])},
  'conditional_kernel_boot_option_execution_contract_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']))
