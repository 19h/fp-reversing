#!/usr/bin/env python3
"""Recover literal-modifier candidate routes and exact source argument setup.
O(original text+6*bounded backward span+2^16) time, O(source spans+2^16) space.
Routing predicates are source-local premises; no native caller/PAC executes.
"""
import json,struct
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS
from recover_daemon_object_creation import sha,span
from recover_daemon_creation_predecessors import literal_pairs
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_cache36 import ida_matches
from replay_daemon_descriptor_producers import unpack
from recover_daemon_iokit_census import text_section
TARGET=0x100aee3a4;INDEX=0x6eca
SPECS=[('new_context',0x100b5c580,0x100b5c620),('existing_context',0x100bae14c,0x100bae180),('callee',0x100aee3a4,0x100aee464),('route_780',0x10078080c,0x100780834),('route_834',0x100834e6c,0x100834ea4),('route_a1',0x100a1e4c8,0x100a1e4ec),('after_unlock',0x100208f00,0x100208f0c),('saved_continuation',0x100bb2278,0x100bb2284)]
def continuation_slots():
 rows=[]
 for a,r in sorted(FIXUPS.items()):
  w=int.from_bytes(IMAGE.read(a,8),'little')
  if r['kind']!='auth-rebase'or(w>>32)&65535!=0x7315 or(w>>48)&7!=0:continue
  index=(a-TABLE)//8;assert(a-TABLE)%8==0 and -(1<<31)<=index<(1<<31);phase=index&0xffffffff;rows.append({'slot':hex(a),'phase32':hex(phase),'signed_table_index':index,'target':hex(r['target']),'new_route_mask_matches':phase&0x6292==0x202,'existing_route_mask_matches':phase&0x6eca==0x240})
 assert len(rows)==13;return rows
def continuation_census():
 a,n=text_section();b=IMAGE.read(a,n);out={}
 for op,name in [(0xf9000000,'stores'),(0xf9400000,'loads')]:
  p=op|((0x2f48//8)<<10)|(31<<5);out[name]=[hex(a+j)for j in range(0,n-3,4)if struct.unpack_from('<I',b,j)[0]&0xffffffe0==p]
 assert out=={'stores':['0x100aee3b0'],'loads':['0x100bb2278']};return {'original_text_start':hex(a),'original_text_size_bytes':n,**out,'scope':'direct unsigned-immediate 64-bit SP-relative encodings only; aliases/overlaps/computed/paired accesses not excluded'}
def phase_biases(slots):
 out=[];M=0xffffffff
 for row in slots:
  for family,offset,flag in [('new_context',0x5e8e,'new_route_mask_matches'),('existing_context',0x5e48,'existing_route_mask_matches')]:
   if not row[flag]:continue
   p=int(row['phase32'],16);d=[]
   for h in range(64):
    t=(((h^0x9aa67aa3)+0xf94f9c00)&M)^(((h^0xece88b77)+0x8f016a2c)&M);r=((p+offset-0x1a9d+0x15a6c96d+(h^0x764ef1d4))&M)^t;d.append(((r+0x9c161ea3)-h)&M)
   out.append({'family':family,'phase32':row['phase32'],'W12':hex((p+offset)&M),'return_target':row['target'],'delta_at_low6_zero':hex(d[0]),'distinct_delta_values32':[hex(x)for x in sorted(set(d))],'all_64_low6_values_have_raw_count':all(x==0 for x in d),'inputs_checked':64})
 assert len(out)==7 and [(x['family'],x['phase32'])for x in out if x['all_64_low6_values_have_raw_count']]==[('new_context','0x32b'),('existing_context','0x371')];return out
def cube(fn):
 rows=[x for x in range(65536)if fn(x)==INDEX];assert rows;allset=65535;anyset=0
 for x in rows:allset&=x;anyset|=x
 mask=(~(allset^anyset))&65535;assert rows==[x for x in range(65536)if x&mask==allset];return {'inputs_checked':65536,'accepted_low16_inputs':len(rows),'mask32':hex(mask),'value32':hex(allset),'first_low16_examples':[hex(x)for x in rows[:8]],'scope':'finite low16 census; all-u32 equivalence proved separately'}
def main():
 census=literal_pairs(0xa86e);assert len(census)==6;slots=[a for a,r in FIXUPS.items()if r['target']==TARGET];assert slots==[TABLE+INDEX*8];live=[]
 for name in ['daemon_digest_routes_ida_bytes.json','daemon_digest_routes_ida_return.json']:live.extend(ida_matches(name))
 xrefs=json.loads((ROOT/'daemon_digest_routes_ida_xrefs.json').read_text());assert not xrefs.get('isError');text='\n'.join(x.get('text','')for x in xrefs['content']);assert '6b117c693e3b'in text and '0x101071540'in text and '0x100aee3a4'in text
 cubes={'new_context':cube(lambda x:(x^0xc58)^((x+0x5e8e)&0xffffffff)),'existing_context':cube(lambda x:((x+0x6a4a)&0xffffffff)^x)};assert cubes['new_context']['mask32']=='0x6292'and cubes['new_context']['value32']=='0x202'and cubes['existing_context']['mask32']=='0x6eca'and cubes['existing_context']['value32']=='0x240'
 observed=[]
 for j,row in enumerate(json.loads((ROOT/'daemon_object_clock_profiles.json').read_text())['cases']):
  t=unpack(row)
  for e in t['edges']:
   if e['pc']=='0x100208f08':assert e['target']=='0x1002a78b8'and e['slot']=='0x101071560';observed.append({'clock_case_index':j,'edge':e})
 assert len(observed)==48
 cont=continuation_slots();branches={hex(i):{'slot':hex(TABLE+i*8),'fixup':FIXUPS[TABLE+i*8]}for i in [0x61b9,0x624a]};extra=[int(x['slot'],16)for x in cont]+[int(x['slot'],16)for x in branches.values()];deps=['daemon_digest_routes_ida_bytes.json','daemon_digest_routes_ida_return.json','daemon_digest_routes_ida_xrefs.json','daemon_identity_cache_contracts.json','daemon_object_initialization_contracts.json','daemon_object_clock_profiles.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'entry':hex(TARGET),'entry_slot':hex(slots[0]),'entry_table_index':hex(INDEX),'entry_FIXUP':verify_used_fixups(slots),'observed_other_slot_FIXUP':verify_used_fixups([0x101071560]),'continuation_FIXUPS':verify_used_fixups(extra),'original_IA7315_continuation_slots':cont,'direct_SP2F48_census':continuation_census(),'continuation_phase_biases':phase_biases(cont),'raw_count_branch_slots':branches,'spans':[span(n,a,z)for n,a,z in SPECS],'literal_A86E_census':census,'compact_routing_cubes':cubes,'retained_after_unlock_edges':observed,'live_IDB_matches':live,'candidate_warning':'Literal-modifier sites and source-local phase predicates do not prove any native caller or upstream reachability. Other modifier constructions and alternate table roots are not excluded. Continuation-slot filtering additionally assumes original cells, a preserved SP+2F48 and return through BB2280.','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_digest_routes_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'literal_candidates':6,'spans':len(SPECS),'low16_inputs':131072,'IDB_ranges':len(live),'IDB_bytes':sum(x['size_bytes']for x in live)}),flush=True)
if __name__=='__main__':main()
