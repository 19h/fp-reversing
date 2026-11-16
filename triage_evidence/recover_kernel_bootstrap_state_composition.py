#!/usr/bin/env python3
"""Pinned source and initialized-data prerequisites for continuous boot/thread state.
O(collection+source+data+symbols) time/space. No native target or IDB mutation.
"""
import json
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_platform_environment_execution as B
K=B.O.B.B.B;T=B.O.B.B
P='kernel_bootstrap_state_composition';ADDITIONS=[K.ENUM,K.SCALAR,K.SETTER,T.POST,T.WRAPPER]
FUNCTIONS=[*B.FUNCTIONS,*ADDITIONS]
FALSE=B.FALSE+['native_initialized_data_lifetime_established','native_thread_handoff_established']
SCOPE='Original main/platform/environment/timer flow continues through original topology enumeration, post-helper and bootstrap-thread copy/setter on bounded private serialized trees. Original initialized topology-page bytes/fixups are an explicit initial-state alternative to the previous zero-page fixture, not a later state repair. The unchanged zero-page case stops before a null record store. Registration and selector0e no-RAM returns, logical PAC/system effects, later main callbacks, native startup and matched daemon/kernel transactions remain conditional or unknown.'

def build():
 im=Image();k=im.k;prior=json.loads(read(ROOT/(B.P+'_checks.json')));old=json.loads(read(ROOT/(B.O.P+'_checks.json')));fs=[B.E.capture(k,a) for a in FUNCTIONS];matches=[]
 for f in fs:
  q=next(q for q in [prior,old] if any(x['start']==f['start'] for x in q['functions']));r=next(x for x in q['functions'] if x['start']==f['start']);assert r['bytes']==f['bytes'] and r['end']==f['end'];matches.append(f['start'])
 strings={int(s['address'],16):s for s in prior['strings']}
 for s in old['strings']:
  a=int(s['address'],16);raw=k.read(a,256).split(b'\0')[0]+b'\0';strings[a]={'address':hex(a),'bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')}
 blocks=[]
 for a,n in [(0xfffffe0007ef8000,4096),(K.TEMPLATE,1472),(K.THREAD,1472),(K.SLOT,8),(K.SLOT_PTR,8),(0xfffffe0007f8b4f0,4),(K.CPU_MAP,256)]:
  raw=b''.join(im.logical_page(pg) for pg in range(a&~4095,(a+n+4095)&~4095,4096));off=a&4095
  blocks.append({'address':hex(a),'size_bytes':n,'raw_hex':k.read(a,n).hex(),'logical_hex':raw[off:off+n].hex()})
 pointers=[im.pointer(a) for a in [K.GLOBALS+0x1c,K.GLOBALS+0x24,K.SLOT_PTR]]
 assert [int(p['target'],16) for p in pointers]==[K.ARRAY,K.CLUSTERS,K.SLOT]
 assert k.read(T.CONTROL,4)==bytes.fromhex('02000000')
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n) for n in [B.P+'_checks.json',B.O.P+'_checks.json','kernel_native_reader.py','kernel_vm_mig_tools.py']},'functions':fs,'matched_prior_functions':matches,'strings':list(strings.values()),'literal_data':prior['literal_data'],'initialized_data':blocks,'pointer_fixups':pointers,'exact_symbols':k.symbols(FUNCTIONS),'verified_counts':{'captured_functions':len(fs),'captured_words':sum(len(f['instructions']) for f in fs),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'matched_prior_functions':len(matches),'captured_strings':len(strings),'literal_blocks':len(prior['literal_data']),'initialized_data_blocks':len(blocks),'pointer_fixups':len(pointers),'opaque_words_preserved':sum(i['mnemonic']=='opaque' for f in fs for i in f['instructions'])},'conditional_kernel_bootstrap_state_composition_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
