#!/usr/bin/env python3
"""Original creator/pair/state source,census,zerofill and SDK static initializer.
O(B+I+text+256R+F+SDK bytes) time/space; no native target or compiled code runs.
"""
import hashlib,json,struct,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,POOL,selected,verify_original_fixups
from recover_daemon_iokit_census import native,text_section
from resolve_kernel_collection_interfaces import macho
from daemon_import_bindings import binding
from probe_daemon_rwlock_lifecycle import RANGES,PRIMARY,SECOND,FALLBACK
LABELS=['paired_creator','creator_entry','allocation','initializer','init_first_gate','init_zero_gate','init_large_gate','init_memory_gate','init_busy_gate','init_generic_error','init_busy_result','publish_pointer','creator_epilogue','state09_publication']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sdk_check():
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());obj=ROOT/'daemon_rwlock_lifecycle_sdk.o';cmd=['xcrun','clang','-target','arm64e-apple-macos26.0','-isysroot',str(sdk),'-Werror','-c',str(ROOT/'daemon_rwlock_lifecycle_sdk.c'),'-o',str(obj)];p=subprocess.run(cmd,capture_output=True,text=True);assert p.returncode==0,p.stderr;data=obj.read_bytes();m=macho(data,0,'SDK initializer object');sec=next(s for s in m['sections']if s['section']=='__const');raw=data[sec['file_offset']:sec['file_offset']+sec['size']];assert len(raw)==200 and raw==struct.pack('<Q',0x2da8b3b4)+bytes(192)and IMAGE.read(0x1010b7478,200)==raw
 hs=[sdk/'usr/include/pthread/pthread.h',sdk/'usr/include/pthread/pthread_impl.h',sdk/'usr/include/sys/_pthread/_pthread_types.h',sdk/'usr/include/sys/errno.h'];return {'command':cmd,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'source_sha256':sha(ROOT/'daemon_rwlock_lifecycle_sdk.c'),'object_sha256':sha(obj),'object_section':sec,'initializer200_hex':raw.hex(),'original_target_address':'0x1010b7478','original_target200_hex':IMAGE.read(0x1010b7478,200).hex(),'headers':[{'path':str(h),'sha256':sha(h)}for h in hs],'scope':'Installed arm64e SDK initializer bytes and signatures; target build equivalence and current runtime contents unknown; object is compiled only.'}
def census():
 a,n=text_section();raw=IMAGE.read(a,n);matches={0x858b:[],0xc81b:[]};primary_pages=[]
 for j,(op,)in enumerate(struct.iter_unpack('<I',raw)):
  pc=a+4*j
  for k in matches:
   if op&0xffffffe0==0xf2a00000|(k<<5):matches[k].append(hex(pc))
  if op&0x9f000000==0x90000000:
   imm=((op>>5)&0x7ffff)<<2|((op>>29)&3);imm=imm-(1<<21)if imm&(1<<20)else imm
   if(pc&~4095)+(imm<<12)==PRIMARY&~4095:primary_pages.append(hex(pc))
 return {'text_address':hex(a),'text_size_bytes':n,'text_sha256':hashlib.sha256(raw).hexdigest(),'MOVK64_lsl16_high16_matches':{hex(k):v for k,v in matches.items()},'ADRP_primary_page_matches':primary_pages,'scope':'Bounded literal high-half and direct primary-page forms only; different encodings,aliases and computed addresses outside census. The C81B match at100C4FE7C belongs to a larger64-bit constant,not established as fallback use.'}
def main():
 spans=[native(n,*r)for n,r in zip(LABELS,RANGES)];rules=[('primary_cell',0x100e99a00,0x100f4e390,0xd7,-0x18,POOL,0xffffffff858becd2),('creator_call',0x100fc4230,0x101031fa0,0xe4,0xcc70,TABLE,0),('second_cell',0x100e99700,0x100f4e190,0x56,0xe6c,POOL,0xffffffffa42562ce),('state_cell',0x100e99a00,0x100f4e390,0x54,0x1cd,POOL,0xfffffffffeff1acd),('creator_controller',0x100e99a00,0x100f4e390,0x78,0x835,POOL,0xffffffffd5be375a),('creator_table',0x100e99a00,0x100f4e390,0x54,0x864,POOL,0xffffffffd0c4d1ee),('malloc',0x100fc4230,0x101031fa0,0xe4,0xcbb0,TABLE,0)]
 banks=[]
 for name,l,r,k,add,base,bias in rules:
  b=selected(l,r,k,add,base,bias);b.update(label=name,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex());banks.append(b)
 p=json.loads((ROOT/'daemon_rwlock_lifecycle_profiles.json').read_text());used={int(e['address'],16)for r in p['cases']for e in r['source_fixup_reads']};used|={FALLBACK,0x1010ab938,0x1010a0f58};used-={0x1010b1e18,0x1010a39c8};fix=verify_original_fixups(used);m=macho(IMAGE.data,0,'fairplayd');sections=[next(s for s in m['sections']if s['address']<=a<s['address']+s['size'])for a in [PRIMARY,SECOND]];assert all(s['flags']&255==1 for s in sections)
 live=json.loads((ROOT/'daemon_rwlock_lifecycle_live_ida.json').read_text());matched=[]
 for row in live['disassembly']['results']:
  for i in row['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;matched.append({'pc':i['address'],'size_bytes':len(raw)})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_rwlock_lifecycle.py','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py','recover_daemon_iokit_census.py','resolve_kernel_collection_interfaces.py','daemon_rwlock_lifecycle_sdk.c','daemon_rwlock_lifecycle_live_ida.json']},'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':banks,'census':census(),'original_fixup_records':fix,'lifecycle_bindings':[binding(a)for a in [0x10109ff58,0x1010a0dd0,0x1010ab938,0x1010a0f58]],'cell_sections':sections,'primary_cell':hex(PRIMARY),'second_cell':hex(SECOND),'fallback_file_initial_fixup':FIXUPS[FALLBACK],'SDK':sdk_check(),'live_IDB_source_rows_matched':matched,'upstream_caller_context_proved':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_rwlock_lifecycle_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'spans':len(spans),'banks':len(banks),'fixups':len(fix['records']),'IDB_rows':len(matched),'SDK_initializer_bytes':200}),flush=True)
if __name__=='__main__':main()
