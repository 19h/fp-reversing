#!/usr/bin/env python3
"""Recover the cold-cache MobileGestalt and CF formatting prefix.
O(source visits+effects+original text bytes) time, O(largest journal) space.
No native allocator, property query, CoreFoundation, IPC or PAC executes.
"""
import json,re,struct,base64,hashlib,subprocess
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from replay_daemon_descriptor_producers import unpack
from recover_daemon_iokit_census import text_section
KEYS=[('SerialNumber',0x1010b1af8,0x100bab21c),('WifiAddress',0x1010b1ab8,0x100c9941c),('BluetoothAddress',0x1010b1a38,0x100a42444),('UniqueChipID',0x1010b1b38,0x100b2c150)]
SPECS=[('cache_publication',0x1009c014c,0x1009c0158),('serial_query',0x100bab198,0x100bab24c),('wifi_query',0x100c993b4,0x100c99448),('bluetooth_query',0x100a42410,0x100a42480),('chip_query',0x100b2c128,0x100b2c180),('number_conversion',0x1009ba7f8,0x1009ba854),('chip_format',0x1009b4254,0x1009b4310),('identity_format',0x100ad6f88,0x100ad6ff8),('failure_frame',0x100bb15a0,0x100bb1620),('frame_producer1',0x1007cfa64,0x1007cfab8),('frame_producer2',0x100ace968,0x100ace9a8),('frame_producer3',0x100bdb258,0x100bdb278)]
def cfstring(a):
 raw=IMAGE.read(a,32);isa,flags,p,n=struct.unpack('<4Q',raw);assert FIXUPS[a]['target']=='CoreFoundation/___CFConstantStringClassReference';p=FIXUPS[a+16]['target'];b=IMAGE.read(p,n);assert IMAGE.read(p+n,1)==b'\0';return {'address':hex(a),'raw32_hex':raw.hex(),'isa_fixup':FIXUPS[a],'flags':hex(flags),'characters':hex(p),'length_u64':n,'characters_hex':b.hex(),'literal':b.decode('ascii'),'character_pointer_fixup':FIXUPS[a+16]}
def ida_matches(name):
 result=json.loads((ROOT/name).read_text());assert not result.get('isError');txt='\n'.join(x.get('text','')for x in result['content']);assert '6b117c693e3b'in txt;match=re.search(r'\[assist:tool-output\]\s*(\{.*\})\s*\[/assist:tool-output\]',txt,re.S);obj=json.loads(match[1]);out=[]
 for row in obj['results']:
  a=int(row['address'],16);b=bytes.fromhex(row['bytes']);assert len(b)==row['size_read']==row['size_requested'];raw=IMAGE.read(a,len(b));different=[]
  for j,(x,y)in enumerate(zip(raw,b)):
   if x!=y:different.append(a+j)
  if different:
   assert len(b)%32==0;allowed=set()
   for j in range(0,len(b),32):
    constant=cfstring(a+j);assert struct.unpack_from('<Q',b,j+16)[0]==int(constant['characters'],16);assert struct.unpack_from('<Q',b,j)[0]==0x1010ca4d8;assert b[j+8:j+16]+b[j+24:j+32]==raw[j+8:j+16]+raw[j+24:j+32];allowed.update([a+j,a+j+16])
   assert all((p&~7)in allowed for p in different)
  out.append({'evidence_file':name,'address':hex(a),'size_bytes':len(b),'original_sha256':hashlib.sha256(raw).hexdigest(),'IDB_sha256':hashlib.sha256(b).hexdigest(),'fixup_normalized_fields':list(sorted({hex(p&~7)for p in different})),'match_kind':'fixup-normalized constant'if different else'raw identical'})
 assert len(out)==obj['count'];return out
def main():
 p=json.loads((ROOT/'daemon_cache36_profiles.json').read_text());pool={};fix=set();totals=Counter();cases=[]
 for r in p['cases']:
  t=unpack(r);pool.update(t['source_pool']);fix.update(int(a,16)for a in t['used_fixups']);apis=t['API_models'];published=[e for e in t['events']if e['kind']=='write'and int(e['address'],16)==0x1010c6840];assert len(published)==1 and published[0]['pc']=='0x1009c0154';assert t['cache_owner_defined_bytes']==0
  cases.append({'clock_case_index':r['clock_case_index'],'configuration':r['configuration'],'source_visits':len(t['steps']),'boundary':r['boundary'],'API_models':apis,'cache_publication':published[0],'cache_owner_defined_bytes':0})
  totals.update({'cases':1,'source_visits':len(t['steps']),'read_effects':sum(e['kind']=='read'for e in t['events']),'write_effects':sum(e['kind']=='write'for e in t['events']),'API_models':len(apis),'logical_edges':len(t['edges'])})
 keys=[]
 for name,a,pc in KEYS:
  row=cfstring(a);h=base64.b64encode(hashlib.md5(('MGCopyAnswer'+name).encode()).digest()).decode()[:22];assert row['literal']==h;row.update({'mapped_property':name,'call_pc':hex(pc),'mapping_hash_recomputed':h});keys.append(row);fix.update([a,a+16])
 constants=[cfstring(a)for a in [0x1010b1a18,0x1010b1b18,0x1010b1a98]]
 for c in constants:fix.update([int(c['address'],16),int(c['address'],16)+16])
 live=[]
 for n in ['daemon_cache36_ida_initial.json','daemon_cache36_ida_key.json','daemon_cache36_ida_more.json','daemon_cache36_ida_conversion.json']:live.extend(ida_matches(n))
 start,n=text_section();section={'start':hex(start),'size_bytes':n};text=IMAGE.read(start,n);encoded=0xf9000000|((0x3050//8)<<10)|(31<<5);writers=[hex(start+j)for j in range(0,len(text)-3,4)if struct.unpack_from('<I',text,j)[0]&0xffffffe0==encoded];assert writers==['0x1007cfa88','0x100ace980','0x100bdb268']
 command=['xcrun','--sdk','macosx','clang','-target','arm64-apple-macos13','-O1','-S',str(ROOT/'daemon_cache36_sdk.c'),'-o',str(ROOT/'daemon_cache36_sdk.s')];run=subprocess.run(command,capture_output=True,text=True);assert run.returncode==0,run.stderr
 deps=['daemon_cache36_context.json','daemon_cache36_profiles.json','daemon_cache36_mgkeys_reference.json','daemon_cache36_sdk.c']+['daemon_cache36_ida_'+n+'.json'for n in ['initial','key','more','conversion']];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':[span(n,a,z)for n,a,z in SPECS],'source_pool':pool,'original_fixups':verify_used_fixups(fix),'MobileGestalt_keys':keys,'other_CFStrings':constants,'live_IDB_matches':live,'direct_SP3050_writer_census':{'original_text':section,'encoding_mask':'0xffffffe0','encoding_value':hex(encoded),'writers':writers,'scope':'STR Xn,[SP,#0x3050] unsigned-immediate encoding only; computed/paired/alias writes not excluded'},'cases':cases,'totals':dict(totals),'SDK_compile':{'command':command,'exit_code':run.returncode,'stdout':run.stdout,'stderr':run.stderr,'assembly_sha256':sha(ROOT/'daemon_cache36_sdk.s'),'native_program_executed':False},'new_port_emission_established':False,'cache_content_or_identity_digest_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache36_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'totals':dict(totals),'opcodes':len(pool),'fixups':len(out['original_fixups']['records']),'IDB_ranges':len(live),'IDB_bytes':sum(x['size_bytes']for x in live)}),flush=True)
if __name__=='__main__':main()
