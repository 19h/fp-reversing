#!/usr/bin/env python3
"""Capture original local stack-probe implementation and reexport provenance.
Read-only cache/image bytes; O(used cache bytes+exports+source census) time,
O(export tries+retained source ranges) space. No native helper or IDB executes.
"""
import json,hashlib,struct
from pathlib import Path
from bootpolicy_cache_reader import Cache,Dylib,uleb
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,TABLE
from recover_daemon_iokit_census import text_section
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1048576):h.update(b)
 return h.hexdigest()
def terminal(d,wanted):
 data=d.export_bytes;rows=[]
 def walk(at,name):
  n,p=uleb(data,at);end=p+n
  if n and name==wanted:
   flags,q=uleb(data,p);payload=data[q:end];row={'name':name,'node_offset':at,'flags':flags,'terminal_payload_hex':payload.hex()}
   if flags&8:
    ordinal,q=uleb(data,q);row.update(reexport_ordinal=ordinal,reexport_name=data[q:end].split(b'\0')[0].decode())
   rows.append(row)
  k=data[end];cur=end+1
  for _ in range(k):
   t=data.index(0,cur);suffix=data[cur:t].decode();child,cur=uleb(data,t+1);walk(child,name+suffix)
 walk(0,'');assert len(rows)==1;return rows[0]
def main():
 c=Cache();compiler=Dylib(c,'/usr/lib/system/libcompiler_rt.dylib');pthread=Dylib(c,'/usr/lib/system/libsystem_pthread.dylib');system=Dylib(c,'/usr/lib/libSystem.B.dylib');alias=terminal(compiler,'___chkstk_darwin');libs=[raw[24:].split(b'\0')[0].decode()for cmd,raw in compiler.commands if cmd in [0xc,0x18,0x8000001f,0x80000023]];assert libs[alias['reexport_ordinal']-1]==pthread.path and alias['reexport_name']=='____chkstk_darwin';a=pthread.exports[alias['reexport_name']]['address'];helper=pthread.function(a);assert helper['start']=='0x180587cd4'and helper['end']=='0x180587d40';reexports=[raw[24:].split(b'\0')[0].decode()for cmd,raw in system.commands if cmd==0x8000001f];assert compiler.path in reexports
 start,n=text_section();raw=IMAGE.read(start,n);census={};
 for value in [0x1803,0xca54]:
  pattern=struct.pack('<II',0xd2800000|(value<<5)|17,0xd73f0911);at=0;rows=[]
  while (at:=raw.find(pattern,at))>=0:
   if at%4==0:rows.append(hex(start+at+4))
   at+=1
  census[hex(value)]={'exact_pattern_hex':pattern.hex(),'aligned_call_PCs':rows,'discriminator_collision_slots':[{'slot':hex(a),'target':hex(r['target'])if isinstance(r['target'],int)else r['target']}for a,r in FIXUPS.items()if f'div=0x{value:04X} 'in r['line']],'complete_caller_graph_proved':False}
 stores=[]
 for j,(word,)in enumerate(struct.iter_unpack('<I',raw)):
  if word&0xffc003e0==0xf90003e0 and ((word>>10)&4095)*8==0x2328:stores.append(hex(start+j*4))
 ranges=[]
 for label,a,z in [('caller_mode471C',0x10039c894,0x10039c974),('eight_byte_allocation',0x10039712c,0x1003971b8),('adapter',0x100abca64,0x100abccc0),('callee_entry',0x100a59bb4,0x100a59e00),('null_output_return',0x10095f074,0x10095f0b8),('nonnull_dispatch',0x100a09c5c,0x100a09c70),('auxiliary_gate',0x1006583b0,0x10065840c)]:
  b=IMAGE.read(a,z-a);ranges.append({'label':label,'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(b,a)]})
 files=[{**c.files[p],'sha256':sha(Path(p))}for p in sorted(c.used)];deps=['bootpolicy_cache_reader.py','daemon_receive_tools.py','recover_daemon_iokit_census.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'source_spans':ranges,'cache_UUID':c.uuid,'cache_files':files,'libraries':[{'path':d.path,'UUID':d.uuid,'base':hex(d.base),'export_trie_sha256':hashlib.sha256(d.export_bytes).hexdigest()}for d in [system,compiler,pthread]],'libSystem_reexports_compiler_rt':True,'compiler_rt_alias':alias,'compiler_rt_loaded_libraries':libs,'pthread_export':terminal(pthread,'____chkstk_darwin'),'stack_probe_original_function':helper,'literal_call_census':census,'literal_SP2328_store_census':{'addresses':stores,'scope':'Aligned unsigned-immediate STR Xn,[SP,#0x2328] in original __text only; paired,unscaled,computed-base stores and SP changes are outside this census.'},'text_address':hex(start),'text_size_bytes':n,'text_sha256':hashlib.sha256(raw).hexdigest(),'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_producers_source.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(ranges),'stack_probe_original_bytes':(int(helper['end'],16)-int(helper['start'],16)),'cache_files_hashed':len(files),'literal_1803_calls':len(census['0x1803']['aligned_call_PCs']),'literal_CA54_calls':len(census['0xca54']['aligned_call_PCs'])}),flush=True)
if __name__=='__main__':main()
