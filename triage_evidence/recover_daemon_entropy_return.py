#!/usr/bin/env python3
"""Original seed-state/time ABI, complete source spans and SDK comparison.
O(source+prefix bytes+256+fixups+SDK bytes) time/space; no target API runs.
"""
import hashlib,json,subprocess
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,selected,verify_original_fixups,FIXUPS
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from resolve_kernel_collection_interfaces import macho
from daemon_entropy_return_restore import restore
from replay_daemon_context_transfer import unpack

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=json.loads((ROOT/'daemon_entropy_return_profiles.json').read_text());prior=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());rows=[]
 for c in p['cases']:
  index=c['prior_case_index'];v=restore(base['cases'][index],next(x for x in prior['cases']if x['prior_case_index']==index));t=unpack(c)
  ptrs={hex(o):hex(v.concrete(z3.Concat(*[v.bytes[v.F+o+j]for j in range(7,-1,-1)]),'saved record pointer'))for o in [0x498,0x580]};assert set(ptrs.values())=={hex(v.F+0x670)}
  assert all(v.F+0x680+j not in v.bytes for j in range(16))and all(not(int(w['address'],16)<v.F+0x690 and int(w['address'],16)+w['size_bytes']>v.F+0x680)for w in t['writes'])
  rows.append({'prior_case_index':index,'frame_SP':hex(v.F),'saved_record_roots':ptrs,'timeval_address':hex(v.F+0x680),'precall_output_source_defined_bytes':0,'precall_output_size_bytes':16,'boundary':t['boundary']})
 spans=[native(n,a,z)for n,a,z in [('entropy_store_and_setup',0x100409578,0x1004095b4),('seed_iteration',0x1002fbee4,0x1002fbf2c),('time_arguments_and_import',0x1002dc290,0x1002dc30c),('time_consumers_and_second_entropy',0x1002dc30c,0x1002dc3a4)]]
 fix={int(a,16)for c in p['cases']for a in c['fixup_addresses']};bank=selected(0x100fc4230,0x101031fa0,0xf3,0xcbc3,TABLE,0);assert int(bank['slot'],16)in fix
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());headers=[]
 for rel in ['usr/include/_stdlib.h','usr/include/sys/time.h','usr/include/sys/_types/_timeval.h','usr/include/c++/v1/__random/mersenne_twister_engine.h']:
  h=sdk/rel;lines=h.read_text().splitlines();terms=['arc4random(void)','gettimeofday(','__darwin_time_t         tv_sec','__darwin_suseconds_t    tv_usec','__x_[__i] = (__f *','    624,','    1812433253>','    mt19937;'];matches=[{'line':j+1,'text':s.strip()}for j,s in enumerate(lines)if any(x in s for x in terms)];headers.append({'path':str(h),'sha256':sha(h),'declarations':matches})
 cmd=['xcrun','clang','-target','arm64e-apple-macos','-std=c11','-fsyntax-only',str(ROOT/'daemon_entropy_return_sdk.c')];result=subprocess.run(cmd,capture_output=True,text=True);assert result.returncode==0
 live=[]
 for name in ['daemon_entropy_return_live_ida.json','daemon_entropy_iteration_live_ida.json','daemon_time_consumers_live_ida.json']:
  obj=json.loads((ROOT/name).read_text());assert obj['target']=='6b117c693e3b'and not obj['idb_mutated']
  for row in obj['instructions']:assert IMAGE.read(int(row['address'],16),len(bytes.fromhex(row['bytes'])))==bytes.fromhex(row['bytes']);live.append(row)
 sections=[s for s in macho(IMAGE.data,0,'daemon')['sections']if s['address']<=0x1010c784c<s['address']+s['size']];assert len(sections)==1 and sections[0]['flags']&255==1
 deps=['daemon_entropy_return_profiles.json','daemon_context_transfer_profiles.json','daemon_arena_storage_profiles.json','daemon_entropy_return_restore.py','daemon_entropy_return_symbolic.py','daemon_entropy_return_sdk.c','daemon_entropy_return_live_ida.json','daemon_entropy_iteration_live_ida.json','daemon_time_consumers_live_ida.json','daemon_import_bindings.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'source_fixup_records':verify_original_fixups(fix),'iteration_slots':[{'index':hex(i),'slot':hex(TABLE+i*8),'fixup':FIXUPS[TABLE+i*8]}for i in [0x5cd3,0x5ced]],'time_bank':bank,'time_binding':binding(int(bank['slot'],16)),'state_section':sections[0],'state_array':{'address':'0x1010c784c','last_word_address':'0x1010c8208','words':624,'word_bits':32,'size_bytes':2496,'seed_store_PC':'0x100409578','iteration_store_PC':'0x1002fbf00','coefficient':'0x6c078965','right_shift':30,'index_first':1,'index_last':623},'contexts':rows,'SDK_headers':headers,'SDK_compile':{'command':cmd,'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'clang_version':subprocess.check_output(['xcrun','clang','--version'],text=True),'scope':'Compile-only installed arm64e SDK ABI; source-build SDK identity unknown.'},'live_IDB_rows_matched':len(live),'native_target_executed':False,'native_entropy_executed':False,'native_time_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_entropy_return_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(spans),'live_IDB_rows':len(live),'fixups':len(fix),'contexts':len(rows),'SDK_compile_exit':result.returncode}),flush=True)
if __name__=='__main__':main()
