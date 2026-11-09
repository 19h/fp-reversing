#!/usr/bin/env python3
"""Audit source effects, UTF-8 byte units, SHA-1 prefix and fresh continuations.
O(parent+new visits+effects+solver resources) time, O(largest journal) space.
No completed digest, cache representation or native IPC is inferred.
"""
import json,struct
from pathlib import Path
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_cache36 import ida_matches
from recover_daemon_object_clock import sections
from replay_daemon_descriptor_producers import unpack
from validate_daemon_object_clock import checked,logical_read,unsat
from capture_daemon_identity_cache import restore
from capture_daemon_object_clock import memory_width
from probe_daemon_identity_cache import Run,configurations,P,SIZE
from prove_daemon_identity_cache import obligations
from recover_daemon_identity_cache import IV
def main():
 c=checked('daemon_identity_cache_contracts.json','recover_daemon_identity_cache.py');ctx=checked('daemon_identity_cache_context.json','capture_daemon_identity_cache.py');p=checked('daemon_identity_cache_proofs.json','prove_daemon_identity_cache.py');r=checked('daemon_identity_cache_profiles.json','probe_daemon_identity_cache.py');counts=Counter();totals=Counter();old=json.loads((ROOT/'daemon_cache36_profiles.json').read_text());oldctx=json.loads((ROOT/'daemon_cache36_context.json').read_text());oldctx={x['clock_case_index']:x for x in oldctx['contexts']};contexts={x['cache_case_index']:x for x in ctx['contexts']};writable=[s for s in sections()if s['segment']=='__DATA'];assert c['source_sha256']==ctx['source_sha256']==r['source_sha256']==sha(SOURCE)
 for saved in ctx['contexts']:
  parent=old['cases'][saved['cache_case_index']];assert parent['payload_sha256']==saved['parent_payload_sha256'];t=unpack(parent);rebuilt=restore(oldctx[saved['clock_case_index']],t)
  for k,v in rebuilt.items():assert saved[k]==v,(saved['cache_case_index'],k)
  counts.update({'restored_parent_contexts':1,'parent_visits_reconstructed':len(t['steps']),'parent_effects_reconstructed':len(t['events'])})
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for pc,row in c['source_pool'].items():assert IMAGE.read(int(pc,16),4).hex()==row['bytes_hex'];counts['distinct_original_opcodes']+=1
 assert verify_used_fixups({int(x['address'],16)for x in c['original_fixups']['records']})==c['original_fixups'];counts['original_fixups']=len(c['original_fixups']['records'])
 live=[]
 for name in ['daemon_identity_cache_ida_initial.json','daemon_identity_cache_ida_more.json']:live.extend(ida_matches(name))
 assert live==c['live_IDB_matches'];counts['live_IDB_ranges']=len(live);counts['live_IDB_bytes']=sum(x['size_bytes']for x in live);bank=c['helper_table_bank256'];left=IMAGE.read(int(bank['left'],16),256);right=IMAGE.read(int(bank['right'],16),256);assert {j^right[left[j]^int(bank['key'],16)]for j in range(256)}=={int(bank['constant'],16)};counts['exhaustive_bank_inputs']=256
 qs,lifts=obligations(c);assert lifts==p['source_lift_counts']
 for (name,pred),proof in zip(qs,p['proofs'],strict=True):
  assert name==proof['name'];unsat(pred);counts['rebuilt_source_obligations_unsat']+=1
  for fk,hk in [('file','sha256'),('original_file','original_sha256')]:
   f=ROOT/proof[fk];assert sha(f)==proof[hk];forms=z3.parse_smt2_file(str(f));assert len(forms)==1;unsat(forms[0]);unsat(z3.Xor(forms[0],pred));counts['SMT_files_unsat_and_formula_matched']+=1
 counts['source_lift_visits']=sum(lifts.values());cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;pool={int(pc,16):next(cs.disasm(bytes.fromhex(row['bytes_hex']),int(pc,16)))for pc,row in c['source_pool'].items()};certificates=[];assert len(r['cases'])==96*len(list(configurations()))==768
 for k,(saved,summary)in enumerate(zip(r['cases'],c['cases'],strict=True)):
  t=unpack(saved);parent=contexts[t['cache_case_index']];cfg=t['configuration'];F=int(t['entry_SP'],16);owner=F+0x3c70;buf=P+0x39000;capacity=cfg['maximum_bytes']+1;cache=int(t['cache_owner_address'],16);data={int(g['address'],16)+j:x for g in parent['known_byte_groups']for j,x in enumerate(bytes.fromhex(g['bytes_hex']))};apis={int(m['pc'],16):m for m in t['API_models']};pos=0;zeros=[];converted=None;inputbytes=None;initialized=False;alive=False;helpers=0
  def put(a,b):data.update({a+j:x for j,x in enumerate(b)})
  def invalidate(a,n):
   for j in range(n):data.pop(a+j,None)
  def read(a,n):assert all(a+j in data for j in range(n)),(k,hex(a),n);return bytes(data[a+j]for j in range(n))
  for e in t['extension_fixtures']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
  for pc,raw in t['steps']:
   i=pool[pc];assert bytes(i.bytes).hex()==raw
   if pc==0x100440be4:helpers+=1
   if pc in apis:
    m=apis[pc];name=m['binding']['symbol'];assert not m['native_call_executed'];ret=int(m['returned_X0'],16)
    if name=='_CFStringCreateWithFormat':assert pc==0x100ad6fcc and m['arguments3']==['0x0','0x0','0x1010b1a98']and read(F,40).hex()==m['variadic_stack40_hex']and ret==(0x6d00006000 if cfg['identity_present']else 0);counts['identity_format_models_checked']+=1
    elif name=='_CFStringGetLength':assert m['arguments1']==['0x6d00006000']and ret==cfg['UTF16_length'];counts['UTF16_length_models_checked']+=1
    elif name=='_CFStringGetMaximumSizeForEncoding':assert m['arguments2']==[hex(cfg['UTF16_length']),'0x8000100']and ret==cfg['maximum_bytes'];counts['maximum_size_models_checked']+=1
    elif name=='_malloc':assert m['requested_bytes']==capacity and ret==(buf if cfg['buffer_nonnull']else 0);counts['allocation_models_checked']+=1;alive=bool(ret);invalidate(buf,capacity)
    elif name=='_CFStringGetCString':
     assert alive and m['arguments4']==['0x6d00006000',hex(buf),hex(capacity),'0x8000100']and ret==int(cfg['conversion_success']);assert zeros==list(range(buf,buf+capacity))and read(buf,capacity)==bytes(capacity);counts['complete_source_zero_fills_checked']+=1;counts['source_zero_fill_bytes_checked']+=len(zeros);text=m['fixture_text'];assert len(text.encode('utf-16-le'))//2==cfg['UTF16_length'];converted=text.encode('utf-8');assert len(converted)+1<=capacity;assert m['writes']==([{'address':hex(buf),'bytes_hex':(converted+b'\0').hex()}]if cfg['conversion_success']else[]);invalidate(buf,capacity)
     for e in m['writes']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
     counts['CString_models_checked']+=1
    elif name=='_strlen':assert alive and converted is not None and read(buf,len(converted)+1)==converted+b'\0'and m['read_prefix_hex']==(converted+b'\0').hex()and ret==len(converted);inputbytes=converted;counts['byte_length_models_checked']+=1
    elif name=='_free':assert alive and m['arguments1']==[hex(buf)];alive=False;invalidate(buf,capacity);counts['free_requests_checked']+=1
    else:assert name=='_CFRelease';counts['CFRelease_requests_checked']+=1
    counts['API_models_checked']+=1;continue
   effects=[]
   if any(o.type==ARM64_OP_MEM for o in i.operands):
    need=memory_width(i);got=0
    while got<need:e=t['events'][pos];pos+=1;assert e['pc']==hex(pc);got+=e['size_bytes'];effects.append(e)
    assert got==need
   for e in effects:
    a=int(e['address'],16);n=e['size_bytes'];b=bytes.fromhex(e['bytes_hex']if e['kind']=='read'else e['after_hex']);assert len(b)==n
    if e['kind']=='read':
     if all(a+j in data for j in range(n)):assert read(a,n)==b,(k,e)
     else:assert not P<=a<a+n<=P+SIZE and not any(s['start']<=a<a+n<=s['start']+s['size_bytes']for s in writable),(k,'undefined read',e);assert logical_read(a,n)==b
     counts['ordered_source_reads_checked']+=1
    else:
     assert not cache<=a<cache+36;put(a,b);counts['ordered_source_writes_checked']+=1
     if pc==0x100accc38:assert n==1 and b==b'\0';zeros.append(a)
   if pc==0x1009153f0:
    assert read(owner+0x40,8)==bytes(8);words=list(struct.unpack('<5I',read(owner+0x48,20)));assert [x^0xf4f92df7 for x in words]==IV and int.from_bytes(read(owner+0x5c,4),'little')==20 and int.from_bytes(read(owner+0x60,4),'little')==2;initialized=True;counts['SHA1_context_initializations_checked']+=1
  assert pos==len(t['events'])and not any(t['cache_owner_defined_mask36']);boundary=t['boundary'];assert boundary==saved['boundary']==summary['boundary']
  if inputbytes is not None:
   assert initialized;assert int.from_bytes(read(owner+0x40,4),'little')==0;counts['shared_helper_calls_checked']+=helpers
   actual=read(owner,64);decoded=bytes(x^0x98 for x in actual)
   if len(inputbytes)<56:
    assert helpers==1 and int.from_bytes(read(owner+0x44,4),'little')==len(inputbytes)
    expected=inputbytes+b'\x80'+bytes(55-len(inputbytes))+(len(inputbytes)*8).to_bytes(8,'big');assert decoded==expected and boundary['pc']=='0x100abee7c'and boundary['detail']['address']==hex(F+0x2e50);counts['SHA1_short_padding_blocks_checked']+=1
   else:assert helpers==0 and int.from_bytes(read(owner+0x44,4),'little')==0 and decoded==inputbytes[:64]and boundary['pc']=='0x100abee84'and boundary['detail']['address']==hex(F+0x2c8c);counts['SHA1_first_input_blocks_checked']+=1
   certificates.append({'case_index':k,'UTF16_code_units':cfg['UTF16_length'],'UTF8_bytes':len(inputbytes),'input_hex':inputbytes.hex(),'context_buffer64_hex':actual.hex(),'decoded_buffer64_hex':decoded.hex(),'boundary_PC':boundary['pc'],'completed_digest_established':False})
  else:assert boundary['pc']=='0x100bb15d0'and boundary['detail']['address']==hex(F+0x3050);counts['SP3050_frontiers_checked']+=1
  assert boundary['kind']=='before_unknown_frame_read';counts['undefined_frame_frontiers_checked']+=1
  totals.update({'source_visits':len(t['steps']),'read_effects':sum(e['kind']=='read'for e in t['events']),'write_effects':sum(e['kind']=='write'for e in t['events']),'API_models':len(t['API_models']),'logical_edges':len(t['edges'])});counts.update({'persisted_A64_cases':1,'source_visits_checked':len(t['steps']),'cache_owner_bytes_defined':0});new=Run(parent,cfg).run();assert new==saved,(k,'fresh case mismatch');counts['freshly_recomputed_A64_cases']+=1
  if k%64==63:print(json.dumps({'cases_checked_and_recomputed':k+1,'source_visits_checked':counts['source_visits_checked']}),flush=True)
 assert dict(totals)=={k:v for k,v in c['totals'].items()if k!='cases'};assert c['SDK_compile']['exit_code']==0
 for name,h in c['SDK_compile']['header_hashes'].items():assert sha(Path(name))==h
 deps=['daemon_identity_cache_context.json','daemon_identity_cache_contracts.json','daemon_identity_cache_profiles.json','daemon_identity_cache_proofs.json','capture_daemon_identity_cache.py','probe_daemon_identity_cache.py','prove_daemon_identity_cache.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'SHA1_prefix_certificates':certificates,'source_lift_counts':lifts,'all_checks_pass':True,'new_port_emission_established':False,'completed_digest_or_cache_content_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_identity_cache_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
