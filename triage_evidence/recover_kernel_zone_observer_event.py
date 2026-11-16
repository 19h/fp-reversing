#!/usr/bin/env python3
"""Capture paired zone observer/wait/wake interfaces and bounded root locators.
O(image bytes + instructions + symbols) time/space; no target/IDB effects.
"""
import bisect,json,struct
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
P='kernel_zone_observer_event';ARM=0xfffffe000bd7332c;FOLLOW=0xfffffe000bd75b54
OBSERVER=0xfffffe0007f213e0;BASE=0xfffffe000caeb480
FUNCTIONS=[ARM,FOLLOW,0xfffffe000bd28394,0xfffffe000bd6e22c,0xfffffe000bd0ab18]
SCOPE='Original paired zone bit4 observer/control1 wait arm and control0 followup/wake; callback pointer/modifier/arguments, post-callback link reads, same-event hash and returning-call/private-component custody. Native callback identities/effects, locking, authentication, blocking, wake delivery, reclamation and daemon transaction identity remain unknown.'
SPANS={
 'arm_flag':(0xfffffe000bd73380,0xfffffe000bd73388),
 'arm_set':(0xfffffe000bd73390,0xfffffe000bd7339c),
 'arm_geometry':(0xfffffe000bd733c0,0xfffffe000bd733d8),
 'arm_id':(0xfffffe000bd733d8,0xfffffe000bd733e8),
 'arm_callback':(0xfffffe000bd733e8,0xfffffe000bd73400),
 'arm_next':(0xfffffe000bd73400,0xfffffe000bd73408),
 'arm_wait':(0xfffffe000bd73408,0xfffffe000bd73414),
 'arm_block':(0xfffffe000bd7341c,0xfffffe000bd7342c),
 'follow_clear':(0xfffffe000bd75b6c,0xfffffe000bd75b78),
 'follow_root':(0xfffffe000bd75b78,0xfffffe000bd75b84),
 'follow_geometry':(0xfffffe000bd75b84,0xfffffe000bd75b9c),
 'follow_id':(0xfffffe000bd75b9c,0xfffffe000bd75bac),
 'follow_callback':(0xfffffe000bd75bac,0xfffffe000bd75bc4),
 'follow_next':(0xfffffe000bd75bc4,0xfffffe000bd75bcc),
 'follow_hash':(0xfffffe000bd75bcc,0xfffffe000bd75c3c),
 'follow_tail':(0xfffffe000bd75c3c,0xfffffe000bd75c5c),
 'wait_hash':(0xfffffe000bd283c0,0xfffffe000bd28434)}
DEPS=['kernel_native_reader.py','kernel_vm_mig_tools.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py',
 'audit_kernel_zone_bitmap_release.py','probe_kernel_zone_bitmap_release.py','kernel_zone_bitmap_release_checks.json',
 'kernel_zone_bitmap_release_audit.json','kernel_zone_startup_profiles.json','aes_event_registration_checks.json',
 'aes_event_wake_selection_checks.json','event_wait_table_checks.json','kernel_retirement_magazines_checks.json']
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_synchronization_established',
 'native_callback_identities_established','native_callback_RAM_effects_established','native_waiter_membership_established',
 'native_wake_delivery_established','physical_page_reclamation_established','daemon_kext_transaction_correlated',
 'new_Mach_port_endpoint_established','full_goal_complete']

def locators(k):
 """ADRP plus nearby immediate access candidates; never an alias census."""
 rows=[];scans=[];seen=set()
 for s in k.kernel['segments']:
  if s['name'] not in ['__TEXT_EXEC','__TEXT_BOOT_EXEC','__KLD']:continue
  raw=k.read(s['address'],s['file_size']);pages=0
  for off in range(0,len(raw)-3,4):
   w=struct.unpack_from('<I',raw,off)[0]
   if w&0x9f000000!=0x90000000:continue
   imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3);imm-=((imm>>20)&1)<<21
   a=s['address']+off;page=((a&~0xfff)+(imm<<12))&((1<<64)-1)
   if page!=OBSERVER&~0xfff:continue
   pages+=1;ii=list(k.cs.disasm(k.read(a,192),a));reg=ii[0].op_str.split(',')[0]
   for i in ii[1:]:
    match=('['+reg+', #0x3e0]') in i.op_str or i.mnemonic=='add' and i.op_str.endswith(', '+reg+', #0x3e0')
    if not match or i.address in seen:continue
    seen.add(i.address);rows.append({'adrp':hex(a),'candidate':hex(i.address),'mnemonic':i.mnemonic,
     'operands':i.op_str,'compiler_function':hex(k.starts[bisect.bisect_right(k.starts,i.address)-1])})
  scans.append({'segment':s['name'],'start':hex(s['address']),'bytes':len(raw),'aligned_words':len(raw)//4,'page_ADRP_candidates':pages})
 return {'window_bytes':192,'scope':'Three kernel executable segments; lexical same-base immediate access after matching ADRP. Other addressing, aliases, clobbers, other fileset code and indirect writers are not closed.',
  'scans':scans,'candidates':rows}

def build():
 image=Image();k=image.k;functions=[k.function(a) for a in FUNCTIONS];prior=json.loads(read(ROOT/'aes_event_registration_checks.json'))
 for f in functions[2:4]:
  old=next(r for r in prior['spans'] if r['start']==f['start']);assert f['bytes']==old['bytes_hex'] and f['sha256']==old['sha256']
 old=json.loads(read(ROOT/'kernel_zone_bitmap_release_checks.json'));assert functions[4]==old['functions'][1]
 spans=[]
 for name,(a,z) in SPANS.items():
  b=k.read(a,z-a);ii=list(k.cs.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 calls=[i for f in functions[:2] for i in f['instructions'] if i['mnemonic'] in ['bl','blraa']]
 direct=sorted({int(i['operands'][1:],16) for i in calls if i['mnemonic']=='bl'})
 sections=[{'entry':e['name'],**s} for e in k.entries for s in e['sections'] if s['address']<=OBSERVER< s['address']+s['size']]
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'dependencies':{n:sha(ROOT/n) for n in DEPS},'functions':functions,'spans':spans,'reused_caller_spans':[],
  'calls':calls,'exact_symbols':k.symbols([*FUNCTIONS,OBSERVER,*direct]),
  'observer_root':{'address':hex(OBSERVER),'original_bytes_hex':k.read(OBSERVER,8).hex(),'section_owners':sections,
   'chained_rebase':image.meta.get(image.offset(OBSERVER)),
   'logical_file_bytes_hex':image.logical_page(OBSERVER&~4095)[OBSERVER&4095:(OBSERVER&4095)+8].hex()},
  'root_locators':locators(k),
  'verified_counts':{'new_complete_functions':2,'new_instructions':sum(len(f['instructions']) for f in functions[:2]),
   'captured_functions':len(functions),'captured_instructions':sum(len(f['instructions']) for f in functions),
   'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'source_blocks':len(spans),
   'block_instructions':sum(len(s['instructions']) for s in spans),'direct_call_sites':sum(i['mnemonic']=='bl' for i in calls),
   'authenticated_indirect_call_sites':sum(i['mnemonic']=='blraa' for i in calls),'original_function_matches':3},
  'conditional_kernel_zone_observer_event_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
