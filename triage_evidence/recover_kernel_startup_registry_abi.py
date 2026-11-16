#!/usr/bin/env python3
"""Pinned startup registry, callback bodies, phase names and dispatch source.
O(collection+source+registry+symbols) time/space. No native target or IDB.
"""
import json,struct
from collections import Counter
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image,INIT
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_bootstrap_state_composition as B
P='kernel_startup_registry_abi';BASE=0xfffffe000cbea1d0;END=0xfffffe000cbfebb8;CURSOR=0xfffffe000cbc9a48
SORT=0xfffffe000c62f4e4;QUICKSORT=0xfffffe000c61b4ec;COMPARE=0xfffffe000c630754;DISPATCH=0xfffffe000c6302c4;PHASE=0xfffffe000bd3ad04
TIMEBASE=0xfffffe000be8b80c;STRNCHK=0xfffffe000be3e790;STRNLEN=0xfffffe000bc9dac0;MEMSET=0xfffffe000c648170;TRACE=0xfffffe000c26ad94
PHASE_NAMES=0xfffffe0007e64530;RATIO=0xfffffe000ca8c000;CALLBACK=0xfffffe000cba4138;EVENTS=0xfffffe000cbc0000;EVENT_STATE=0xfffffe0007f1260c;LAST_PHASE=0xfffffe000cb62ec8
TUNABLE=0xfffffe000c6303d4
ADDITIONS=[SORT,QUICKSORT,COMPARE,DISPATCH,PHASE,TIMEBASE,STRNCHK,STRNLEN,MEMSET,TRACE]
FALSE=B.FALSE+['native_startup_callbacks_executed','native_MIG_startup_phase_attested','all_registry_callback_effects_established']
SCOPE='Original startup registry and all 115 registered callback bodies are captured. Source-defined unsigned phase/rank ordering, format-8 callback/argument pointers, phase names, 22 tree/boot-option tunable descriptors, phase14 mach_ipc MIG-initializer registration and dispatcher ABI are recovered. Original main continues from source-produced bootstrap thread through timebase/checked string copy/trace, complete 3519-record sorting and its first original tunable callback/return/cursor publication. Remaining callback effects, native PAC/system/loader lifetime, completion of earlier phases and matched daemon/kernel transactions remain unknown.'

def build():
 im=Image();k=im.k;rows=[];names=[]
 section=next(s for s in k.kernel['sections'] if s['address']==BASE);assert section['segment']=='__BOOTDATA' and section['section']=='__init_entry_set' and section['size']==END-BASE==84456
 def owner(a):
  return sorted({e['name'] for e in k.entries if any(s['address']<=a<s['address']+s['vm_size'] for s in e['segments'])})
 for index,a in enumerate(range(BASE,END,24)):
  phase,rank=struct.unpack('<II',k.read(a,8));callback=im.pointer(a+8);arg=im.pointer(a+16) if k.read(a+16,8)!=bytes(8) else None
  assert callback['format']==8 and callback['auth']==1 and callback['diversity']=='0x2abe' and callback['address_diversity']==0 and callback['key']==0
  target=int(callback['target'],16);assert target in k.starts and owner(target)==['com.apple.kernel']
  logical=struct.pack('<IIQQ',phase,rank,target,int(arg['target'],16) if arg else 0)
  rows.append({'index':index,'address':hex(a),'phase_u32':phase,'rank_u32':rank,'raw_hex':k.read(a,24).hex(),'logical_hex':logical.hex(),'callback_pointer':callback,'callback_owner':owner(target),'argument_pointer':arg,'argument_owner':owner(int(arg['target'],16)) if arg else []})
 for phase in range(20):
  a=PHASE_NAMES+8*phase;pointer=im.pointer(a) if k.read(a,8)!=bytes(8) else None
  raw=k.read(int(pointer['target'],16),256).split(b'\0')[0]+b'\0' if pointer else None
  names.append({'phase':phase,'pointer':pointer,'name':raw[:-1].decode('ascii') if raw else None,'bytes_hex':raw.hex() if raw else None})
 targets=sorted({int(r['callback_pointer']['target'],16) for r in rows});functions=list(dict.fromkeys([*B.FUNCTIONS,*ADDITIONS,*targets]));fs=[B.B.E.capture(k,a) for a in functions];symbols=k.symbols(functions)
 prior=json.loads(read(ROOT/(B.P+'_checks.json')));matched=[]
 for f in prior['functions']:
  new=next(x for x in fs if x['start']==f['start']);assert new['bytes']==f['bytes'] and new['end']==f['end'];matched.append(f['start'])
 mig=json.loads(read(ROOT/'kernel_vm_mig_source.json'));old=next(f for f in mig['functions'] if f['start']==hex(INIT));new=next(f for f in fs if f['start']==hex(INIT));assert old['bytes']==new['bytes'] and old['end']==new['end']
 inventory=[]
 for a in targets:
  f=next(f for f in fs if f['start']==hex(a));indices=[r['index'] for r in rows if int(r['callback_pointer']['target'],16)==a]
  inventory.append({'target':hex(a),'end':f['end'],'source_sha256':f['sha256'],'words':len(f['instructions']),'registry_indices':indices,'phase_histogram':dict(Counter(str(rows[j]['phase_u32']) for j in indices)),'exact_symbols':symbols[hex(a)],'direct_calls':[{'PC':i['ea'],'kind':i['mnemonic'],'target':i['operands'][1:]} for i in f['instructions'] if i['mnemonic']=='bl']})
 tunables=[]
 for r in rows:
  if int(r['callback_pointer']['target'],16)!=TUNABLE:continue
  a=int(r['argument_pointer']['target'],16);pointers={};texts={}
  for off,key in [(0,'path'),(8,'property'),(24,'option'),(32,'destination')]:
   p=im.pointer(a+off) if k.read(a+off,8)!=bytes(8) else None;pointers[key]=p
   if key!='destination':texts[key]=k.read(int(p['target'],16),256).split(b'\0')[0].decode('ascii') if p else None
  size=int.from_bytes(k.read(a+40,4),'little');dst=int(pointers['destination']['target'],16);assert 0<size<=64
  raw=b''.join(im.logical_page(pg) for pg in range(dst&~4095,(dst+size+4095)&~4095,4096));off=dst&4095
  tunables.append({'registry_index':r['index'],'descriptor':hex(a),'raw_hex':k.read(a,48).hex(),'pointers':pointers,**texts,'destination':hex(dst),'size_bytes':size,'path_flags_byte10':k.read(a+16,1)[0],'normalize_byte2c':k.read(a+44,1)[0],'initial_destination_hex':raw[off:off+size].hex()})
 assert len(tunables)==22
 strings=[]
 for a in [0xfffffe000706217c,0xfffffe000704fa23,0xfffffe0007062704,0xfffffe000706529e,0xfffffe00070652db,0xfffffe000704fa64]:
  raw=k.read(a,256).split(b'\0')[0]+b'\0';strings.append({'address':hex(a),'bytes_hex':raw.hex(),'text':raw[:-1].decode('ascii')})
 registered=[r for r in rows if int(r['callback_pointer']['target'],16)==INIT];assert len(registered)==1 and registered[0]['index']==123 and registered[0]['phase_u32']==14 and registered[0]['rank_u32']==0 and names[14]['name']=='mach_ipc'
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n) for n in [B.P+'_checks.json','kernel_vm_mig_source.json','kernel_native_reader.py','kernel_vm_mig_tools.py']},'functions':fs,'matched_prior_functions':matched,'strings':strings,'exact_symbols':symbols,'fixup_base':hex(im.base),'registry':{'base':hex(BASE),'end':hex(END),'size_bytes':END-BASE,'stride_bytes':24,'section':section,'raw_sha256':sha256(k.read(BASE,END-BASE)).hexdigest(),'logical_sha256':sha256(b''.join(bytes.fromhex(r['logical_hex']) for r in rows)).hexdigest(),'entries':rows,'phase_histogram':dict(Counter(str(r['phase_u32']) for r in rows))},'callback_inventory':inventory,'tunable_descriptors':tunables,'phase_names':names,'initial_cursor_pointer':im.pointer(CURSOR),'MIG_initializer_registration':{'entry_index':123,'phase':14,'phase_name':'mach_ipc','rank':0,'callback':hex(INIT),'argument_pointer':registered[0]['argument_pointer'],'prior_source_sha256':sha(ROOT/'kernel_vm_mig_source.json')},'verified_counts':{'captured_functions':len(fs),'captured_words':sum(len(f['instructions']) for f in fs),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'matched_bootstrap_functions':len(matched),'registry_records':len(rows),'registry_bytes':END-BASE,'unique_callbacks':len(targets),'null_arguments':sum(r['argument_pointer'] is None for r in rows),'phase_name_slots':len(names),'named_phases':sum(r['name'] is not None for r in names),'registered_callback_words':sum(i['words'] for i in inventory),'tunable_descriptors':len(tunables),'opaque_words_preserved':sum(i['mnemonic']=='opaque' for f in fs for i in f['instructions'])},'conditional_kernel_startup_registry_abi_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
