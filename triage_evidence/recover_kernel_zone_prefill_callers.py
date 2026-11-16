#!/usr/bin/env python3
"""Pinned prefill bodies and collection-wide direct-branch locator.
O(collection bytes + captured instructions + symbols) time/space. Aligned
branch encodings are candidates; indirect references/reachability stay open.
"""
import bisect,json,struct
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
P='kernel_zone_prefill_callers'
PREFILL=0xfffffe000bd730f8;ARM=0xfffffe000bd7332c;SMALL=0xfffffe000bd7ab0c
FUNCTIONS=[PREFILL,0xfffffe000bd71c10,SMALL,ARM,0xfffffe000bd0aab4]
SPANS={
 'quota_gate':(0xfffffe000bd73120,0xfffffe000bd7312c),
 'quota_clear':(0xfffffe000bd7312c,0xfffffe000bd7313c),
 'count_A':(0xfffffe000bd731b4,0xfffffe000bd731c0),
 'count_B':(0xfffffe000bd73200,0xfffffe000bd7320c),
 'boolean':(0xfffffe000bd732e8,0xfffffe000bd732f0),
 'small_result':(0xfffffe000bd7ac54,0xfffffe000bd7ac58),
 'small_count':(0xfffffe000bd7ac58,0xfffffe000bd7ac60),
 'small_arm':(0xfffffe000bd7ac60,0xfffffe000bd7ac68),
 'small_sentinel':(0xfffffe000bd7ac68,0xfffffe000bd7ac70)}
SCOPE='Original two-partition prefill, Boolean return, direct incoming call sites, conditional caller lock/request context and source-produced arm early-return join. Private source components use explicit list-provider, lock, monitor, zeroing and retirement models. Native callback effects, synchronization, scheduler admission, indirect caller completeness and daemon transaction identity remain unknown.'
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_synchronization_established',
 'native_list_provider_effects_established','native_blocking_established','all_indirect_callers_established',
 'physical_page_reclamation_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']

def scan(k):
 seen=set();sections=[];calls=[]
 for e in k.entries:
  for s in e['sections']:
   key=(s['address'],s['size'])
   if key in seen or not s['flags']&0x80000400:continue
   seen.add(key);raw=k.read(s['address'],s['size']&~3)
   sections.append({'entry':e['name'],'segment':s['segment'],'section':s['section'],
    'address':hex(s['address']),'bytes_scanned':len(raw),'aligned_words':len(raw)//4,'sha256':__import__('hashlib').sha256(raw).hexdigest()})
   for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
    if w&0x7c000000!=0x14000000:continue
    pc=s['address']+4*j;imm=w&0x3ffffff;imm-=((imm>>25)&1)<<26;target=(pc+4*imm)&((1<<64)-1)
    if target not in [PREFILL,ARM]:continue
    i=next(k.cs.disasm(raw[j*4:j*4+4],pc));assert i.mnemonic==('bl' if w>>31 else 'b') and int(i.op_str[1:],16)==target
    calls.append({'entry':e['name'],'pc':hex(pc),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'target':hex(target),
     'kernel_compiler_function':hex(k.starts[bisect.bisect_right(k.starts,pc)-1]) if e['name']=='com.apple.kernel' else None})
 return {'sections':sections,'aligned_words':sum(s['aligned_words'] for s in sections),'direct_branch_candidates':calls,
  'deduplicated_section_ranges':True,'reachable_code_established':False,'indirect_reference_completeness_established':False}

def build():
 k=Kernel();functions=[k.function(a) for a in FUNCTIONS];spans=[]
 for name,(a,b) in SPANS.items():
  raw=k.read(a,b-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 prior=json.loads(read(ROOT/'kernel_zone_observer_event_checks.json'));assert functions[3]==prior['functions'][0]
 old=json.loads(read(ROOT/'kernel_cache_gate_source.json'));assert any(f['start']==functions[4]['start'] and f['bytes']==functions[4]['bytes'] and f['sha256']==functions[4]['sha256'] for f in old['functions'])
 loc=scan(k);targets=[PREFILL,ARM,SMALL,FUNCTIONS[1],0xfffffe000bd0aab4,0xfffffe000bd7497c,0xfffffe000bd74bec,0xfffffe000bd74fcc,0xfffffe000c6480c0,0xfffffe000bd75e20]
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_vm_mig_tools.py','probe_kernel_vm_mig.py',
   'kernel_zone_observer_event_checks.json','kernel_cache_gate_source.json','audit_kernel_zone_bitmap_release.py']},
  'functions':functions,'spans':spans,'reused_caller_spans':[],'direct_branch_scan':loc,'exact_symbols':k.symbols(targets),
  'verified_counts':{'captured_functions':len(functions),'captured_instructions':sum(len(f['instructions']) for f in functions),
   'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'prefill_instructions':len(functions[0]['instructions']),
   'source_blocks':len(spans),'block_instructions':sum(len(s['instructions']) for s in spans),
   'matched_prior_functions':2,'scan_aligned_words':loc['aligned_words'],'direct_branch_candidates':len(loc['direct_branch_candidates'])},
  'conditional_kernel_zone_prefill_callers_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
