#!/usr/bin/env python3
"""Independently audit defined bytes, original source, proofs and fresh cases.
O(parent+new visits+effects+solver resources) time, O(largest journal) space.
Library outputs are declared fixtures. No target/host property or IPC executes.
"""
import json,base64,hashlib,struct
from pathlib import Path
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_MEM
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from recover_daemon_object_creation import sha,span
from recover_daemon_descriptor_producers import verify_used_fixups
from replay_daemon_descriptor_producers import unpack
from recover_daemon_cache36 import ida_matches,cfstring,KEYS
from recover_daemon_object_clock import sections
from validate_daemon_object_clock import checked,logical_read,unsat
from capture_daemon_cache36 import restore
from capture_daemon_object_clock import memory_width
from probe_daemon_cache36 import Run,configurations,P,SIZE
from prove_daemon_cache36 import obligations
def main():
 c=checked('daemon_cache36_contracts.json','recover_daemon_cache36.py');ctx=checked('daemon_cache36_context.json','capture_daemon_cache36.py');p=checked('daemon_cache36_proofs.json','prove_daemon_cache36.py');r=checked('daemon_cache36_profiles.json','probe_daemon_cache36.py');counts=Counter();totals=Counter();writable=[s for s in sections()if s['segment']=='__DATA'];parents=json.loads((ROOT/'daemon_object_clock_context.json').read_text());oldprofiles=json.loads((ROOT/'daemon_object_clock_profiles.json').read_text())
 assert c['source_sha256']==ctx['source_sha256']==r['source_sha256']==sha(SOURCE)
 for saved in ctx['contexts']:
  old=oldprofiles['cases'][saved['clock_case_index']];assert old['payload_sha256']==saved['parent_payload_sha256'];t=unpack(old);rebuilt=restore(parents['contexts'][saved['parent_case_index']],t)
  for k,v in rebuilt.items():assert saved[k]==v,(saved['clock_case_index'],k)
  counts.update({'restored_parent_contexts':1,'parent_source_visits_reconstructed':len(t['steps']),'parent_effects_reconstructed':len(t['events'])})
 for s in c['spans']:assert span(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for pc,row in c['source_pool'].items():assert IMAGE.read(int(pc,16),4).hex()==row['bytes_hex'];counts['distinct_original_opcodes']+=1
 assert verify_used_fixups({int(x['address'],16)for x in c['original_fixups']['records']})==c['original_fixups'];counts['original_fixups']=len(c['original_fixups']['records'])
 live=[]
 for name in ['daemon_cache36_ida_initial.json','daemon_cache36_ida_key.json','daemon_cache36_ida_more.json','daemon_cache36_ida_conversion.json']:live.extend(ida_matches(name))
 assert live==c['live_IDB_matches'];counts['live_IDB_ranges']=len(live);counts['live_IDB_bytes']=sum(x['size_bytes']for x in live)
 ref=json.loads((ROOT/'daemon_cache36_mgkeys_reference.json').read_text())
 for (name,a,pc),row in zip(KEYS,c['MobileGestalt_keys'],strict=True):
  assert cfstring(a)=={k:v for k,v in row.items()if k not in ['mapped_property','call_pc','mapping_hash_recomputed']};h=hashlib.md5(('MGCopyAnswer'+name).encode()).digest();key=base64.b64encode(h).decode()[:22];assert key==row['literal'];assert any(x['clear_key']==name and x['MD5_hex']==h.hex()and x['obfuscated_key']==key for x in ref['direct_hash_checks']);counts['MobileGestalt_key_hashes_recomputed']+=1
 qs,lifts=obligations(c);assert lifts==p['source_lift_counts']
 for (n,pred),proof in zip(qs,p['proofs'],strict=True):
  assert n==proof['name'];unsat(pred);counts['rebuilt_source_obligations_unsat']+=1
  for fk,hk in [('file','sha256'),('original_file','original_sha256')]:
   f=ROOT/proof[fk];assert sha(f)==proof[hk];forms=z3.parse_smt2_file(str(f));assert len(forms)==1;unsat(forms[0]);unsat(z3.Xor(forms[0],pred));counts['SMT_files_unsat_and_formula_matched']+=1
 counts['source_lift_visits']=sum(lifts.values());cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;pool={int(pc,16):next(cs.disasm(bytes.fromhex(row['bytes_hex']),int(pc,16)))for pc,row in c['source_pool'].items()};ctxmap={x['clock_case_index']:x for x in ctx['contexts']};certificates=[]
 assert len(r['cases'])==len(ctx['contexts'])*len(list(configurations()))==432
 for k,(saved,summary)in enumerate(zip(r['cases'],c['cases'],strict=True)):
  t=unpack(saved);parent=ctxmap[saved['clock_case_index']];cfg=saved['configuration'];F=int(t['entry_SP'],16);data={int(g['address'],16)+j:x for g in parent['known_byte_groups']for j,x in enumerate(bytes.fromhex(g['bytes_hex']))};apis={int(x['pc'],16):x for x in t['API_models']};pos=0;published_at=query_at=None;cache=P+cfg['heap_offset'];malloc_seen=False;number=None
  def put(a,b):data.update({a+j:x for j,x in enumerate(b)})
  def read(a,n):assert all(a+j in data for j in range(n)),(k,hex(a),n);return bytes(data[a+j]for j in range(n))
  for stepindex,(pc,raw)in enumerate(t['steps']):
   i=pool[pc];assert bytes(i.bytes).hex()==raw
   if pc in apis:
    m=apis[pc];name=m['binding']['symbol'];assert not m['native_call_executed']
    if name=='_malloc':
     assert not malloc_seen and pc==0x1009c0148 and m['requested_bytes']==36 and int(m['returned'],16)==cache;malloc_seen=True
     for j in range(36):data.pop(cache+j,None)
     counts['declared_nonnull_allocations']=counts['declared_nonnull_allocations']+1
    elif name=='_MGCopyAnswer':
     if query_at is None:query_at=stepindex
     key=next(x for x in c['MobileGestalt_keys']if x['call_pc']==hex(pc));assert m['key_CFString']==key['address']and m['property_mapping']==key['mapped_property']and m['observed_X1']=='0x0';assert published_at is not None and published_at<stepindex;counts['MobileGestalt_models_checked']+=1
    elif name=='_CFNumberGetValue':
     assert m['arguments3']==['0x6d00004000','0x4',hex(F+0x2b70)]and int(m['returned_X0'],16)&0xffffffff==cfg['number_return_W0'];number=cfg['chip_value64'].to_bytes(8,'little');assert m['writes']==[{'address':hex(F+0x2b70),'bytes_hex':number.hex()}];put(F+0x2b70,number);counts['CFNumber_models_checked']+=1
    elif name=='_CFStringCreateWithFormat':
     assert pc==0x1009b42d4 and m['arguments3']==['0x0','0x0','0x1010b1b18']and read(F,8)==number;assert m['variadic_stack'][0]['bytes_hex']==number.hex()and m['format_literal']=='%qi';counts['chip_format_models_checked']+=1
    else:assert name=='_CFRelease';assert m['arguments1'][0]in ['0x1010b1a18']+[hex(0x6d00000000+0x1000*j)for j in range(1,6)];counts['release_requests_checked']+=1
    counts['API_models_checked']+=1;continue
   es=[]
   if any(x.type==ARM64_OP_MEM for x in i.operands):
    need=memory_width(i);got=0
    while got<need:e=t['events'][pos];pos+=1;assert e['pc']==hex(pc);got+=e['size_bytes'];es.append(e)
    assert got==need
   for e in es:
    a=int(e['address'],16);n=e['size_bytes'];b=bytes.fromhex(e['bytes_hex']if e['kind']=='read'else e['after_hex']);assert len(b)==n
    if e['kind']=='read':
     if all(a+j in data for j in range(n)):assert read(a,n)==b,(k,e)
     else:assert not P<=a<a+n<=P+SIZE and not any(s['start']<=a<a+n<=s['start']+s['size_bytes']for s in writable),(k,'undefined read',e);assert logical_read(a,n)==b
     counts['ordered_source_reads_checked']+=1
    else:
     assert not cache<=a<cache+36;put(a,b);counts['ordered_source_writes_checked']+=1
     if a==0x1010c6840:assert pc==0x1009c0154 and int.from_bytes(b,'little')==cache;published_at=stepindex
  assert pos==len(t['events'])and malloc_seen and published_at is not None and query_at>published_at and t['cache_owner_defined_bytes']==0 and read(0x1010c6840,8).hex()==t['cache_pointer_cell_hex'];counts['cache_publication_order_certificates']+=1
  success=cfg['chip_present']and cfg['number_return_W0']!=0 and cfg['format_present'];boundary=t['boundary'];assert boundary==saved['boundary']==summary['boundary']
  if success:
   assert boundary['pc']=='0x100ad6fcc'and boundary['detail']['binding']['symbol']=='_CFStringCreateWithFormat'and boundary['detail']['arguments8'][:3]==['0x0','0x0','0x1010b1a98'];expected=[0x6d00001000,0x1010b1a18,0x6d00005000,0x6d00002000,0x6d00003000];assert [int.from_bytes(read(F+8*j,8),'little')for j in range(5)]==expected;counts['identity_five_vararg_frontiers_checked']+=1;certificates.append({'case_index':k,'stack_arguments5':[hex(x)for x in expected],'format_CFString':'0x1010b1a98','format_literal':'%@%@%@%@%@'})
  else:assert boundary['pc']=='0x100bb15d0'and boundary['kind']=='before_unknown_frame_read'and boundary['detail']['address']==hex(F+0x3050)and any(F+0x3050+j not in data for j in range(8));counts['undefined_frame_frontiers_checked']+=1
  counts.update({'persisted_A64_cases':1,'source_visits_checked':len(t['steps']),'cache_owner_bytes_defined':0});totals.update({'source_visits':len(t['steps']),'read_effects':sum(e['kind']=='read'for e in t['events']),'write_effects':sum(e['kind']=='write'for e in t['events']),'API_models':len(t['API_models']),'logical_edges':len(t['edges'])});new=Run(parent,cfg).run();assert new==saved,(k,'fresh case mismatch');counts['freshly_recomputed_A64_cases']+=1
  if k%48==47:print(json.dumps({'cases_checked_and_recomputed':k+1}),flush=True)
 assert dict(totals)=={k:v for k,v in c['totals'].items()if k!='cases'};assembly=(ROOT/'daemon_cache36_sdk.s').read_text();assert sha(ROOT/'daemon_cache36_sdk.s')==c['SDK_compile']['assembly_sha256']and c['SDK_compile']['exit_code']==0
 for s in ['str\tx0, [sp]','stp\tx3, x4, [sp, #24]','stp\tx1, x2, [sp, #8]']:assert s in assembly
 deps=['daemon_cache36_context.json','daemon_cache36_contracts.json','daemon_cache36_profiles.json','daemon_cache36_proofs.json','capture_daemon_cache36.py','probe_daemon_cache36.py','prove_daemon_cache36.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'identity_vararg_certificates':certificates,'source_lift_counts':lifts,'all_checks_pass':True,'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache36_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
