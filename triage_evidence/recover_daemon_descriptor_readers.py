#!/usr/bin/env python3
"""Original descriptor-reader, table, import, frame and conditional ABI contracts.
O(source spans+retained events+LC_FUNCTION_STARTS) time/space. Original bytes
and bounded live IDB ranges are evidence; semantic native reachability is not.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,FIXUPS,selected,qword
from daemon_import_bindings import binding
from recover_daemon_callback_revisit import verify_fixups
from recover_daemon_context_lock import ida_output
from resolve_kernel_collection_interfaces import commands
SPANS=[('root_bank_publications',0x100387df0,0x100387e40),('root_bank_parameters',0x100387e68,0x100387e70),('reader_A',0x10021ecf4,0x10021ee94),('zero_count_cleanup',0x10025c4e0,0x10025c580),('nonzero_pointer_and_phase',0x10025f0bc,0x10025f0fc),('reader_B',0x100a636ec,0x100a6379c),('reader_B_entry',0x100a59bb4,0x100a59c00),('reader_B_cursor',0x100a59d0c,0x100a59d18),('acquire_callee_prekey_multiply',0x10043e3ac,0x10043e3e0),('acquire_callee_unpack',0x10043e3e0,0x10043e3ec)]
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def envelopes():
 data=SOURCE.read_bytes();at=next(o for o,c,n in commands(data,0)if c==0x26);off,n=struct.unpack_from('<II',data,at+8);a=0x100000000;out=[];j=off
 while j<off+n:
  value=shift=0
  while True:
   b=data[j];j+=1;value|=(b&127)<<shift;shift+=7
   if not b&128:break
  if value==0:break
  a+=value;out.append(a)
 return [{'candidate':hex(pc),'start':hex(max(a for a in out if a<=pc)),'end':hex(min(a for a in out if a>pc)),'semantic_source_function_ownership_proved':False}for pc in [0x10021ecf4,0x100a636ec]]
def main():
 p=json.loads((ROOT/'daemon_descriptor_readers_profiles.json').read_text());spans=[];fix={0x1010b1e28,0x10106d6a8,0x10107f4c8};points=Counter();paths=[]
 for name,a,z in SPANS:
  b=IMAGE.read(a,z-a);ins=list(CS.disasm(b,a));assert len(ins)*4==len(b);spans.append({'label':name,'start':hex(a),'end':hex(z),'bytes_hex':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 banks=[dict(label='reader_A_global',**selected(0x100e99a00,0x100f4e390,0x78,0x61a,POOL,0xffffffffd5a43965)),dict(label='reader_A_acquire',**selected(0x100fc4130,0x101031ea0,0xa3,0xcb81)),dict(label='reader_A_cleanup',**selected(0x100e99700,0x100f4e190,0x81,0xcb5b)),dict(label='reader_B_global',**selected(0x100fc4230,0x101031fa0,0x6c,0x634,POOL,0xffffffffd5a43965))]
 for b in banks:fix.add(int(b['slot'],16))
 for r in p['cases']:
  fix.update(int(e['address'],16)for e in r['source_fixup_reads']);reads=[e for e in r['source_reads']if int(e['address'],16)in [0x1010c8218,0x1010c8220,0x1010c8228]];points.update(e['pc']for e in reads);paths.append({'configuration':r['configuration'],'reader_calls':r['reader_calls'],'reader_returns':r['reader_returns'],'descriptor_reads':reads,'primitive_calls':r['sync_models'],'staged_source_transitions':r['staged_source_transitions'],'boundary':r['boundary']})
 live=ida_output(json.loads((ROOT/'daemon_descriptor_readers_live_ida.json').read_text()));matches=[]
 for r in live['results']:
  a=int(r['address'],16);b=bytes.fromhex(r['bytes']);assert IMAGE.read(a,len(b))==b;partial=[]
  for i in r['instructions']:
   ib=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(ib))==ib and len(ib)<=i['size']
   if len(ib)<i['size']:partial.append({'address':i['address'],'display_bytes':len(ib),'logical_size_bytes':i['size']})
  matches.append({'address':hex(a),'size_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'instruction_rows_checked':len(r['instructions']),'partial_macro_rows':partial})
 xrefs=ida_output(json.loads((ROOT/'daemon_descriptor_readers_ida_retry.json').read_text()));xrefrows=[]
 for r in xrefs['results']:
  for x in r['xrefs_to']:
   a=int(x['from'],16);assert x['type']=='data'and qword(a)==int(r['address'],16);xrefrows.append({'candidate':r['address'],'slot':hex(a),'original_target':hex(qword(a))})
 probe=binding(0x1010b1e28);assert probe['symbol']=='___chkstk_darwin'and(int(probe['word'],16)>>48)&1==1
 env=envelopes();assert[(r['start'],r['end'])for r in env]==[('0x100013f0c','0x10040ebd4'),('0x100a59bb4','0x100abca64')]
 deps=['daemon_descriptor_readers_profiles.json','daemon_descriptor_guard_profiles.json','daemon_descriptor_readers_live_ida.json','daemon_descriptor_readers_ida_retry.json','daemon_context_lock_contracts.json','daemon_iokit_sync_contracts.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'spans':spans,'banks_exhaustive256':banks,'original_fixups':verify_fixups(fix),'conditional_paths':paths,'descriptor_read_PCs':dict(points),'live_IDB_byte_matches':matches,'live_IDB_incoming_data_xrefs':xrefrows,'compiler_function_start_envelopes':env,'entry_B_stack_probe_binding':probe,'entry_B_stack':{'probe_argument_W9_bytes':57072,'local_reservation_bytes':57072,'fixed_save_bytes':96,'total_frame_reservation_bytes':57168,'cursor_increment_bytes':160,'native_stack_probe_special_ABI':'unknown','bank_frame_producer':'unknown'},'phase_premises':{'reader_A_W25':'0x43c9','reader_A_decoded_acquire_control32':'0x593d','reader_A_native_incoming_phase':'unknown','reader_A_nonzero_W23':'unknown; physical backing is varied, execution stops before use','reader_B_native_incoming_phase':'unknown'},'native_target_executed':False,'live_IDB_automatic_analysis_complete':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_readers_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'paths':len(paths),'spans':len(spans),'banks256':len(banks),'fixups':len(out['original_fixups']['records']),'IDB_bytes':sum(r['size_bytes']for r in matches)}),flush=True)
if __name__=='__main__':main()
