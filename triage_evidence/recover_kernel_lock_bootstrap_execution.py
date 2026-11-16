#!/usr/bin/env python3
"""Pinned phase-three lock descriptors and original constructor closure.
Linear source/registry bytes and interval sorting; no target or IDB mutation.
"""
import json,struct
from collections import Counter
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_timeout_execution as B
P='kernel_lock_bootstrap_execution';GROUP=0xfffffe000c62d698;ATTR=0xfffffe000c62d5e8;FIRST=0xfffffe000c62d618
MUTEX=0xfffffe000c62e678;RW=0xfffffe000c62e720;SPIN=0xfffffe000c62e734;TICKET=0xfffffe000c62e788;PLAIN=0xfffffe000c62e7a8
REGLOCK=0xfffffe000bceb154;FIXED=0xfffffe000c631e44;LATE=0xfffffe000bd37dc0
CONSTRUCT=0xfffffe000bd037e0;ALLOC_ID=0xfffffe000bceb1d0;RW_INIT=0xfffffe000bd0622c
FRONTIER=0xfffffe000bd64ea4;STOP=0xfffffe000c639e3c
ADDITIONS=[CONSTRUCT,ALLOC_ID,RW_INIT,FRONTIER];DISPATCH=B.DISPATCH;REGISTRY=0xfffffe000ca90368;BANK=0xfffffe000cb606d8;BITMAP=0xfffffe000ca902e8
SCOPE='Pinned original phase-three startup lock constructors, descriptor bindings and static group-ID allocation. Private continuous execution; native scheduling, authentic PAC, later initialization and matched FairPlay transactions remain unknown.'

def build():
 im=Image();prior=json.loads(read(ROOT/(B.P+'_checks.json')));fs=list(prior['functions'])
 for a in ADDITIONS:
  assert hex(a) not in {f['start'] for f in fs};fs.append(B.B.B.B.B.B.E.capture(im.k,a))
 registry=json.loads(read(ROOT/'kernel_startup_registry_abi_checks.json'))['registry']['entries'];rs=[r for r in registry if r['phase_u32']==3];ds=[]
 for r in rs:
  t=int(r['callback_pointer']['target'],16);a=int(r['argument_pointer']['target'],16) if r['argument_pointer'] else 0;d={'registry_index':r['index'],'target':hex(t),'argument':hex(a),'pointers':[]}
  n={GROUP:80,ATTR:16,MUTEX:24,RW:24,SPIN:16,TICKET:8,PLAIN:8}.get(t,0)
  if n:
   raw=im.k.read(a,n);d['raw_hex']=raw.hex()
   for off in ([0] if t in [GROUP,ATTR,TICKET,PLAIN] else ([0,8] if t==SPIN else [0,8,16])):
    d['pointers'].append(im.pointer(a+off) if raw[off:off+8]!=bytes(8) else None)
   d['destination']=d['pointers'][0]['target']
   if t==GROUP:d.update(name=raw[8:72].split(b'\0')[0].decode('ascii'),flags_u32=struct.unpack_from('<I',raw,72)[0])
   if t==ATTR:d.update(set_mask_u32=struct.unpack_from('<I',raw,8)[0],clear_mask_u32=struct.unpack_from('<I',raw,12)[0])
  ds.append(d)
 strings=[]
 for a in [0xfffffe000704cf1e,0xfffffe000704adcf,0xfffffe000704ada8]:
  raw=im.k.read(a,256).split(b'\0')[0]+b'\0';strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')})
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':im.k.sha256,'prior_checks_sha256':sha(ROOT/(B.P+'_checks.json')),'functions':fs,'added_functions':list(map(hex,ADDITIONS)),'registrations':rs,'descriptors':ds,'strings':strings,'static_group_registry':{'address':hex(REGISTRY),'raw_hex':im.k.read(REGISTRY,0xe8).hex(),'bank_pointer':im.pointer(REGISTRY),'bitmap_pointer':im.pointer(REGISTRY+0x60),'bank_raw_hex':im.k.read(BANK,8192).hex(),'bitmap_raw_hex':im.k.read(BITMAP,128).hex()},'constants':[{'address':hex(a),'bytes_hex':im.k.read(a,8).hex()} for a in [0xfffffe000700dc58,0xfffffe000700dd08]],'exact_symbols':im.k.symbols([*ADDITIONS,*set(int(r['callback_pointer']['target'],16) for r in rs)]),'verified_counts':{'captured_functions':len(fs),'captured_words':sum(len(f['instructions']) for f in fs),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'added_functions':len(ADDITIONS),'registrations':len(rs),'families':dict(Counter(r['callback_pointer']['target'] for r in rs))}}

def regions(e):
 out=[(REGISTRY,0xe8),(BANK,8192),(BITMAP,128),(0xfffffe000cb60590,0x148),(0xfffffe0007e635c8,4),(0xfffffe0007e63610,4),(0xfffffe000cac4200,0x80),(0xfffffe000cb2a5e0,16),(0xfffffe000caaf868,0x148),(0xfffffe000caad718,0x148)]
 for d in e['descriptors']:
  t=int(d['target'],16);a=int(d['argument'],16)
  if 'destination' in d:out.append((int(d['destination'],16),0x148 if t==GROUP else 4 if t==ATTR else 16))
  if t in [MUTEX,RW,SPIN] and d['pointers'][1]:out.append((int(d['pointers'][1]['target'],16),0x148))
  if t==REGLOCK:out.append((a,0xe8))
 return out

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
