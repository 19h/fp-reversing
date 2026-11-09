#!/usr/bin/env python3
"""Recover clock/tail/lock/value-lookup/cache interfaces from original source.
O(source visits+effects+source bytes+256 bank inputs) time, O(largest journal)
space. Source-local cache allocation is separate from executed continuations.
"""
import json,re,struct,subprocess,hashlib
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,selected
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from replay_daemon_descriptor_producers import unpack

SPECS=[('first_clock_setup',0x100bad430,0x100bad4cc),('first_gate',0x100bad4cc,0x100bad508),('second_clock',0x10087cb7c,0x10087cc0c),('clock_success',0x100d2fa40,0x100d2fa58),('tail_fields',0x1009b2a54,0x1009b2ac8),('lazy_gate',0x10064ffbc,0x100650004),('acquire_caller',0x100933c2c,0x100933ce8),('callback_trampoline',0x100c02f3c,0x100c02f44),('query_gate',0x1009d92d0,0x1009d9318),('count_gate',0x100963c9c,0x100963cf0),('scan_setup',0x100b252e8,0x100b25384),('pointer_gate',0x10094cbb8,0x10094cbec),('scan_read',0x10095e930,0x10095e970),('query_compare',0x1008bb504,0x1008bb53c),('matched_value',0x1008f2434,0x1008f245c),('save_value',0x100c11a28,0x100c11a40),('save_status',0x1009512ac,0x1009512cc),('cold_cache_gate',0x100a42d68,0x100a42db0),('cold_cache_allocate',0x1009c00e0,0x1009c0190),('creator_state',0x10043a334,0x10043a364),('acquire_state',0x10043e374,0x10043e3ac),('cleanup_state',0x1004424e0,0x10044251c),('timestamp_environment',0x100abd668,0x100abd71c),('scan_step',0x100839154,0x100839198),('scan_match_index',0x100b328c8,0x100b328cc)]
def ida_rows(r):
 assert not r.get('isError');text='\n'.join(x.get('text','')for x in r['content']);assert '6b117c693e3b'in text
 out=[]
 for m in re.finditer(r'^\s*(0x[0-9a-fA-F]+)\t([^\n]+)\n\s+bytes: ([0-9a-fA-F ]+)$',text,re.M):
  a=int(m[1],16);cols=m[2].split('\t');b=bytes.fromhex(m[3]);assert len(b)==int(cols[-1])==int(cols[-2]);assert IMAGE.read(a,len(b))==b;out.append({'start':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'bytes_hex':b.hex()})
 assert len(out)==int(re.search(r'\bcount: (\d+)',text)[1]);return out
def sections():
 raw=SOURCE.read_bytes();off=32;out=[]
 for _ in range(struct.unpack_from('<I',raw,16)[0]):
  cmd,nb=struct.unpack_from('<II',raw,off)
  if cmd==0x19:
   initprot=struct.unpack_from('<I',raw,off+60)[0]
   for j in range(struct.unpack_from('<I',raw,off+64)[0]):
    p=off+72+80*j;sec,seg,a,n,fo,align,rel,nrel,flags=struct.unpack_from('<16s16sQQ5I',raw,p);out.append({'segment':seg.rstrip(b'\0').decode(),'section':sec.rstrip(b'\0').decode(),'start':a,'size_bytes':n,'flags':hex(flags),'initial_protection':initprot})
  off+=nb
 return out
def main():
 profiles=json.loads((ROOT/'daemon_object_clock_profiles.json').read_text());ctx=json.loads((ROOT/'daemon_object_clock_context.json').read_text());rows=[];pool={};fix=set();totals=Counter()
 for r in profiles['cases']:
  t=unpack(r);F=int(t['entry_SP'],16);writes=[e for e in t['events']if e['kind']=='write'];table=[e for e in t['events']if 0x6800034000<=int(e['address'],16)<0x6800034040];obj=[e for e in writes if 0x6800005000<=int(e['address'],16)<0x6800005368];sampler=[e for e in writes if e['pc']=='0x100b8e7e0'];state=[e for e in writes if 0x1010c784c<=int(e['address'],16)<0x1010c820c];runtime=[e for e in writes if int(e['address'],16)<0x102000000 and not 0x1010c784c<=int(e['address'],16)<0x1010c820c]
  row={'parent_case_index':r['parent_case_index'],'outcome':r['outcome'],'source_visits':r['source_visits'],'boundary':r['boundary'],'API_models':t['API_models'],'extension_fixtures':t['extension_fixtures'],'object_writes':obj,'table_effects':table,'runtime_non_state_writes':runtime,'lookup_outputs':[e for e in writes if int(e['address'],16)in [F+0x344c,F+0x2ae8,F+0x3508]],'cursor_writes':[e for e in writes if int(e['address'],16)==F+0x3620],'sampler':{'attempts':len(sampler),'zero_retries':sum(e['after_hex']=='00'for e in sampler),'unique_addresses':len({e['address']for e in sampler}),'address_min':min((int(e['address'],16)for e in sampler),default=0),'address_max':max((int(e['address'],16)for e in sampler),default=0)},'state_word_writes':len(state),'new_object_publication_established':False};rows.append(row);pool.update(t['source_pool']);fix.update(int(a,16)for a in t['used_fixups']);totals.update({'cases':1,'source_visits':len(t['steps']),'read_effects':sum(e['kind']=='read'for e in t['events']),'write_effects':len(writes),'API_models':len(t['API_models']),'logical_edges':len(t['edges'])})
 spans=[span(n,a,z)for n,a,z in SPECS];bank=selected(0x100e99a00,0x100f4e390,0x6d,0xcb3d,TABLE,0);assert bank['target']=='libSystem/_malloc';fix.add(int(bank['slot'],16));indices=[0x5f16,0x5f52,0x7aeb,0x7aec,0x7ccd,0x7cfd,0x9e58,0x9e5c,0x7f4];slots=[{'index':hex(i),'slot':hex(TABLE+8*i),'fixup':FIXUPS[TABLE+8*i]}for i in indices];fix.update(int(x['slot'],16)for x in slots)
 live=[]
 for name in ['daemon_object_clock_ida_retry.json','daemon_object_clock_ida_more.json']:live.extend(ida_rows(json.loads((ROOT/name).read_text())))
 owners=[]
 for a,n in [(0x1010c67c0,8),(0x1010c4e18,8),(0x1010c4670,8),(0x1010c5040,8),(0x1010b66a8,8),(0x1010b6738,8),(0x1010ca2b0,4),(0x1010c9288,8),(0x1010c6840,8),(0x1010b6cc0,8)]:
  sec=next(x for x in sections()if x['start']<=a<a+n<=x['start']+x['size_bytes']);assert sec['initial_protection']&2;owners.append({'address':hex(a),'size_bytes':n,'section':sec,'native_value':'unknown'})
 parent=json.loads((ROOT/'daemon_object_initialization_profiles.json').read_text());parent_evidence=[]
 for j,old in enumerate(parent['cases'][:3]):
  t=unpack(old);F=int(t['entry_SP'],16);pcs=[a for a,b in t['steps']if t['source_pool'][hex(a)]['mnemonic']=='ldr'and t['source_pool'][hex(a)]['operands']=='x20, [sp, #0x2b50]'];assert pcs;es=[e for e in t['events']if int(e['address'],16)in [F+0x2ab8,F+0x2b50,F+0x3588]or e['pc']==hex(pcs[-1])];aux=[e for e in t['events']if e['kind']=='read'and any(a<=int(e['address'],16)<a+n for a,n in [(0x1010c5040,8),(0x1010b66a8,8),(0x1010b6738,8),(0x1010ca2b0,4),(0x1010c9288,8),(0x1010c6840,8)])];assert not aux;parent_evidence.append({'parent_case_index':j,'last_X20_reload':hex(pcs[-1]),'saved_input_and_status_effects':es,'new_runtime_cells_read_in_parent':len(aux)})
 sdkold=json.loads((ROOT/'daemon_entropy_return_contracts.json').read_text());cmd=sdkold['SDK_compile']['command'];sdk=subprocess.run(cmd,capture_output=True,text=True);assert sdk.returncode==0
 deps=['daemon_object_clock_context.json','daemon_object_clock_profiles.json','daemon_object_clock_ida_bytes.json','daemon_object_clock_ida_retry.json','daemon_object_clock_ida_more.json','daemon_object_initialization_profiles.json','probe_daemon_object_clock.py','daemon_entropy_return_sdk.c','daemon_mode471c_lifecycle_contracts.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'source_pool':pool,'original_fixups':verify_used_fixups(fix),'slots':slots,'cold_cache_bank256':bank,'cases':rows,'totals':dict(totals),'runtime_owners':owners,'parent_data_provenance':parent_evidence,'live_IDB_matches':live,'SDK_compile':{'command':cmd,'exit_code':sdk.returncode,'stdout':sdk.stdout,'stderr':sdk.stderr,'native_program_executed':False},'new_object_publication_established':False,'new_port_emission_established':False,'native_AEE_caller':'unknown','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_clock_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_spans':len(spans),'source_opcodes':len(pool),'fixups':len(out['original_fixups']['records']),'live_IDB_bytes':sum(x['size_bytes']for x in live),'totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
