#!/usr/bin/env python3
"""Recover compression frame/copy contracts from source and frozen journals.
O(text bytes+retained visits/effects) time; O(loaded artifacts+largest decoded
journal) space. No retained frontier is resumed with invented frame inputs.
"""
import hashlib,json,struct
from collections import Counter
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,FIXUPS
from recover_daemon_object_creation import sha,span
from recover_daemon_iokit_census import text_section
from recover_daemon_cache36 import ida_matches
from recover_daemon_descriptor_producers import verify_used_fixups
from replay_daemon_descriptor_producers import unpack
SPECS=[('long_prepare',0x100bb18ec,0x100bb195c),('copy_loop',0x100b3940c,0x100b39450),('copy_finish',0x100926e88,0x100926ec0),('short_call',0x10094a390,0x10094a3b0),('frame_common',0x100abee44,0x100abef18),('compression_entry',0x100b76438,0x100b764ac),('selector_gate',0x100d9f60c,0x100d9f660),('selector_high',0x100b0a24c,0x100b0a29c),('selector_low',0x1009a0398,0x1009a03d4),('other_root_writer',0x1005f5190,0x1005f51dc),('other_root_reader',0x100554c64,0x100554cb8),('raw_capture',0x100aee3a4,0x100aee3c0),('raw_input_reader',0x100a4a08c,0x100a4a0c8),('short_return',0x1009de090,0x1009de0c8),('long_return',0x100c0b4d4,0x100c0b4ec),('next_block_gate',0x100b51c00,0x100b51c8c),('compression_return',0x100bdfaf0,0x100bdfb2c)]
K=0x34385513
def signed8(x):return (x&255)-256 if x&128 else x&255
def selector_reference(b):
 h=0xa710;v=signed8(b+h-((b<<1)&0x77777777)+0x31)
 one=((h+0x3e39c4ab)&0xffffffff)&0x41c5b5c7;four=((h^0xa665)*23)&0xffffffff
 high=v<signed8(one^0xffffffc3);first=h^((four^0x21b0)if high else 0)
 if high:
  p=((one+0x85c325b9)&0xffffffff)&0x7a3cffdf
  test=((one+0x9c8fc3ad)&0xffffffff)^15
  leaf=one^((p^0x3cbe)if (v&255)==(test&255)else 0)
 else:
  p=four^0x669f;test=(p+0x3124)&0xffffffff
  leaf=four^((1<<5)if (v&255)==(test&255)else 0)
 return {'transformed_signed_byte':v,'first_index':first,'leaf_index':leaf,'leaf_target':FIXUPS[TABLE+8*leaf]['target']}
def census():
 a,n=text_section();raw=IMAGE.read(a,n);patterns={};rows=[]
 for off in [0x2e50,0x2c8c,0x3490,0x2de0]:
  for op,scale,name in [(0xf9400000,8,'read64'),(0xf9000000,8,'write64'),(0xb9400000,4,'read32'),(0xb9000000,4,'write32')]:
   if off%scale==0:patterns[op|((off//scale)<<10)|(31<<5)]=(off,name)
 for j in range(0,n-3,4):
  w=struct.unpack_from('<I',raw,j)[0]
  if (w&0xffffffe0)in patterns:
   off,kind=patterns[w&0xffffffe0];i=next(CS.disasm(raw[j:j+4],a+j));rows.append({'address':hex(a+j),'offset':hex(off),'kind':kind,'bytes_hex':raw[j:j+4].hex(),'instruction':i.mnemonic+' '+i.op_str})
 return {'text_start':hex(a),'text_size_bytes':n,'text_sha256':hashlib.sha256(raw).hexdigest(),'scope':'Direct unsigned-immediate scalar32/64 SP operands at four exact offsets only; excludes overlapping other offsets, paired/computed/alias accesses.','records':rows}
def retained():
 old=json.loads((ROOT/'daemon_identity_cache_profiles.json').read_text());counts=Counter();rows=[]
 for idx,row in enumerate(old['cases']):
  cfg=row['configuration']
  if not(cfg['identity_present']and cfg['buffer_nonnull']and cfg['conversion_success']):continue
  t=unpack(row);F=int(t['entry_SP'],16);short=cfg['UTF16_length']<64;regs=[int(v,16)for v in row['boundary']['registers31']];C=F+0x3c70
  assert regs[1]==0x318c and regs[4]==C and regs[10]==0x100b76438 and regs[30]==TABLE and regs[20]==(0x58 if short else 0xe)
  relevant=[e for e in t['edges']if e['target']in ['0x100926e88','0x100abee44']]
  expected=[('0x10094a3ac','0x100abee44')]if short else [('0x100b3944c','0x100926e88'),('0x100926ebc','0x100abee44')]
  assert [(e['pc'],e['target'])for e in relevant]==expected
  writes=[e for e in t['events']if e['kind']=='write'and e['pc']=='0x100926ea4'];assert len(writes)==(0 if short else 1)
  if writes:assert int(writes[0]['address'],16)==F+0x2e50 and int.from_bytes(bytes.fromhex(writes[0]['after_hex']),'little')==C
  assert not any(pc in [0x100aee3a4,0x100b76438]for pc,h in t['steps'])
  for e in t['events']:
   if e['kind']=='write'and e['pc']=='0x100abee80':assert int.from_bytes(bytes.fromhex(e['after_hex']),'little')==C
  counts['short_frontiers'if short else'long_frontiers']+=1;counts['retained_visits_inspected']+=len(t['steps']);counts['retained_effects_inspected']+=len(t['events']);counts['retained_cases_checked']+=1
  rows.append({'case_index':idx,'parent_payload_sha256':row['payload_sha256'],'short':short,'SP':hex(F),'context':hex(C),'compression_continuation_index':hex(regs[20]),'actual_edges':relevant,'SP2E50_finish_writes':writes,'frontier':row['boundary']['pc']})
 assert counts['short_frontiers']==288 and counts['long_frontiers']==192;return rows,dict(counts)
def main():
 rows,counts=retained();selectors=[{'selector_byte':b,**selector_reference(b)}for b in range(256)];indices={0x71c3,0x71b7,0x385f,0x36c8,0x318c,0xe,0x58,0x42,0xa34a,0xa351}|{s['first_index']for s in selectors}|{s['leaf_index']for s in selectors};slots=[{'index':hex(i),'slot':hex(TABLE+8*i),'fixup':FIXUPS[TABLE+8*i]}for i in sorted(indices)];live=ida_matches('daemon_compression_frame_ida_bytes.json')+ida_matches('daemon_compression_frame_ida_return.json');deps=['daemon_compression_frame_ida_bytes.json','daemon_compression_frame_ida_return.json','daemon_identity_cache_profiles.json','daemon_identity_cache_context.json','daemon_digest_conventions_checks.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':[span(n,a,z)for n,a,z in SPECS],'direct_SP_census':census(),'selector256':selectors,'slots':slots,'original_fixups':verify_used_fixups([int(s['slot'],16)for s in slots]),'retained_cases':rows,'retained_counts':counts,'live_IDB_matches':live,'new_port_emission_established':False,'completed_digest_or_cache_content_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_compression_frame_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(SPECS),'fixups':len(slots),'selectors':len(selectors),'retained':counts,'IDB_bytes':sum(x['size_bytes']for x in live)}),flush=True)
if __name__=='__main__':main()
