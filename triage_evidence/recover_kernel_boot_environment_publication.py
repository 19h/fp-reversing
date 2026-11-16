#!/usr/bin/env python3
"""Pinned boot-environment publisher, direct callers and inline tree setup.
O(collection + scanned words + captured bytes + symbols) time/space. Static only.
"""
import bisect,json,struct
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha

P='kernel_boot_environment_publication'
MAIN=0xfffffe000c639a40;PLATFORM=0xfffffe000c5e6620
EARLY=0xfffffe000c660ad4;GENERIC=0xfffffe000c6622b8
STRLCPY=0xfffffe000be3e3c4;STRLEN=0xfffffe000bc9db70;COPY=0xfffffe000c647f10
SECONDARY=0xfffffe000be75bf0;COLD=0xfffffe000c65c050
STATE=0xfffffe0007f8b648;TREE=0xfffffe0007f8b508;ARGS=0xfffffe0007e6d1e0;HEADER=0xfffffe0007e6d660
PATTERN=0xfffffe00070eac3d;LITERAL=0xfffffe000700ebc0
NEXT_TREE=0xfffffe000c5e5894;NEXT_CONTEXT=0xfffffe000c5e5d98
FUNCTIONS=[MAIN,PLATFORM,EARLY,GENERIC,STRLCPY,STRLEN,COPY,SECONDARY,COLD]
SCAN_NAMES=['__TEXT_EXEC','__TEXT_BOOT_EXEC','__KLD']
FALSE=['native_target_executed','native_IPC_executed','hardware_PAC_executed','authentic_boot_inputs_established','daemon_kernel_pairing_established','full_goal_complete']
SCOPE='Pinned kernel boot-environment pointer publication and inline serialized-tree bounds. Original main copies and platform publisher execute to explicit helper boundaries in private memory. Two pre-copy registration helpers have declared no-RAM returns. Later platform helpers, native entry admission, hardware PAC, indirect caller completeness and daemon pairing remain unknown.'

def capture(k,a):
 b=k.starts[bisect.bisect_right(k.starts,a)];raw=k.read(a,b-a);rows=[]
 for pc in range(a,b,4):
  ins=list(k.cs.disasm(k.read(pc,4),pc));rows.append({'ea':hex(pc),'mnemonic':ins[0].mnemonic if ins else 'opaque','operands':ins[0].op_str if ins else '', 'bytes_hex':k.read(pc,4).hex()})
 return {'start':hex(a),'end':hex(b),'bytes':raw.hex(),'sha256':sha256(raw).hexdigest(),'instructions':rows}

def census(k):
 targets={PLATFORM,EARLY,GENERIC};segments=[];edges=[]
 for s in k.kernel['segments']:
  if s['name'] not in SCAN_NAMES:continue
  raw=k.read(s['address'],s['file_size']);assert len(raw)%4==0
  segments.append({'name':s['name'],'start':hex(s['address']),'size_bytes':len(raw),'words':len(raw)//4,'sha256':sha256(raw).hexdigest()})
  for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
   if w&0x7c000000!=0x14000000:continue
   pc=s['address']+j*4;off=(w&0x3ffffff)<<2
   if off&0x8000000:off-=0x10000000
   target=(pc+off)&0xffffffffffffffff
   if target in targets:
    edges.append({'PC':hex(pc),'kind':'bl' if w&0x80000000 else 'b','target':hex(target),'compiler_start':hex(k.starts[bisect.bisect_right(k.starts,pc)-1]),'bytes_hex':k.read(pc,4).hex()})
 return {'scope':'Every aligned word in the three named file-backed kernel executable segments; no indirect, other-fileset or external caller completeness claim.','segments':segments,'targets':list(map(hex,sorted(targets))),'edges':edges}

def build():
 k=Kernel();fs=[capture(k,a) for a in FUNCTIONS];prior=json.loads(read(ROOT/'kernel_boot_header_handoff_checks.json'));matches=[]
 for f in fs:
  q=next((q for q in prior['functions'] if q['start']==f['start']),None)
  if q:assert q['bytes']==f['bytes'] and q['end']==f['end'];matches.append(f['start'])
 c=census(k);pattern=k.read(PATTERN,25);assert pattern==b'BBBBBBBBGGGGGGGGRRRRRRRR\0'
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_boot_header_handoff_checks.json','kernel_boot_option_execution_checks.json']},
  'functions':fs,'matched_prior_functions':matches,'direct_branch_census':c,
  'literal_data':[{'address':hex(PATTERN),'bytes_hex':pattern.hex()},{'address':hex(LITERAL),'bytes_hex':k.read(LITERAL,16).hex()}],
  'exact_symbols':k.symbols([*FUNCTIONS,STATE,STATE+0xa0,TREE]),
  'verified_counts':{'captured_functions':len(fs),'captured_words':sum(len(f['instructions']) for f in fs),'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fs),'matched_prior_functions':len(matches),'scanned_executable_segments':len(c['segments']),'scanned_words':sum(s['words'] for s in c['segments']),'direct_platform_calls':sum(e['target']==hex(PLATFORM) for e in c['edges']),'direct_early_tree_calls':sum(e['target']==hex(EARLY) for e in c['edges']),'direct_generic_tree_calls':sum(e['target']==hex(GENERIC) for e in c['edges']),'opaque_words_preserved':sum(i['mnemonic']=='opaque' for f in fs for i in f['instructions'])},
  'conditional_kernel_boot_environment_publication_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']))
