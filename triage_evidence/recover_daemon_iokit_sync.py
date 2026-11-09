#!/usr/bin/env python3
"""Original selected synchronization/entry/return source, BSS and SDK contracts.
O(B+I+256R+F+SDK bytes) time/space. No native target/API/PAC executes.
"""
import hashlib,json,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,POOL,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from resolve_kernel_collection_interfaces import macho
from probe_daemon_iokit_sync import RANGES,PRIMARY,FALLBACK,ONCE,CALLBACK,PRIMITIVES
LABELS=['outer_entry','acquire_caller','acquire_adapter','acquire_fallback','write_lock','acquire_epilogue','once_callback','callback_leaf','cleanup_caller','cleanup_adapter','cleanup_fallback','unlock','cleanup_epilogue','outer_result_return']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sdk_check():
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());cmd=['xcrun','clang','-target','arm64e-apple-macos26.0','-isysroot',str(sdk),'-fsyntax-only','-Werror',str(ROOT/'daemon_iokit_sync_sdk.c')];p=subprocess.run(cmd,capture_output=True,text=True);assert p.returncode==0,p.stderr
 hs=[sdk/'usr/include/pthread/pthread.h',sdk/'usr/include/sys/_pthread/_pthread_once_t.h'];return {'command':cmd,'source_sha256':sha(ROOT/'daemon_iokit_sync_sdk.c'),'headers':[{'path':str(h),'sha256':sha(h)}for h in hs],'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'scope':'Installed SDK signatures and pointer/___ widths; native synchronization and target-build equivalence unknown.'}
def main():
 spans=[native(n,*r)for n,r in zip(LABELS,RANGES)];banks=[]
 for name,l,r,k,a,bias in [('outer_controller',0x100e99700,0x100f4e190,0x81,0x823,0xffffffffc51978d5),('primary_pointer_cell',0x100fc4230,0x101031fa0,0x6c,-0x13,0xffffffff858becd2)]:
  row=selected(l,r,k,a,POOL,bias);row.update(label=name,base=hex(POOL),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex());banks.append(row)
 assert [b['target']for b in banks]==['0x1010b8e48',hex(PRIMARY)]
 m=macho(IMAGE.data,0,'fairplayd');seg=next(s for s in m['segments']if s['address']<=PRIMARY<s['address']+s['vm_size']);sec=next(s for s in m['sections']if s['address']<=PRIMARY<s['address']+s['size']);assert PRIMARY>=seg['address']+seg['file_size']and sec['flags']&255==1
 live=json.loads((ROOT/'daemon_iokit_sync_live_ida.json').read_text());matched=[]
 for row in live['disassembly']['results']:
  for i in row['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;matched.append({'pc':i['address'],'size_bytes':len(raw)})
 prof=json.loads((ROOT/'daemon_iokit_sync_profiles.json').read_text());used={int(e['address'],16)for r in prof['cases']for e in r['source_fixup_reads']};used-={0x1010b1e18,0x1010a39c8};fix=verify_original_fixups(used)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_iokit_sync.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','recover_daemon_iokit_census.py','resolve_kernel_collection_interfaces.py','daemon_iokit_sync_live_ida.json','daemon_iokit_sync_sdk.c']},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'original_fixup_records':fix,'bindings':[binding(a)for a in sorted({v[1]for v in PRIMITIVES.values()})],'primary_pointer_cell':hex(PRIMARY),'primary_segment':seg,'primary_section':sec,'fallback_pointer_cell':hex(FALLBACK),'fallback_file_initial_fixup':FIXUPS[FALLBACK],'once_control':hex(ONCE),'once_callback':hex(CALLBACK),'live_IDB_source_rows_matched':matched,'SDK':sdk_check(),'native_target_executed':False,'native_synchronization_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_sync_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(spans),'banks':len(banks),'fixups':len(fix['records']),'live_IDB_rows':len(matched),'SDK_exit':0}),flush=True)
if __name__=='__main__':main()
