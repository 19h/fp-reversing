#!/usr/bin/env python3
"""Independent special-space, bound reply-port and turnstile lifetime validation.
O(image+source+visits+RAM+effects), O(image+RAM+journals), three scalar SMT queries.
Raw storage/retirement, initialization/call epochs, packet representation and
logical PAC are explicit; no native bootstrap/namespace/IPC/VM effects execute.
"""
import json,struct
from collections import Counter
from z3 import BitVec,LShR,And,ULE,UGE,ULT,Solver,unsat
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
from replay_rpc502_vm_handoff import decode
from replay_kernel_special_reply import Replay
from replay_kernel_zone_startup import Replay as ZoneReplay
from replay_kernel_reply_namespace import Replay as NamespaceReplay
from replay_kext_constructor_request import Replay as ConstructorReplay
P='kernel_special_reply';B=0x6500000000;SIZE=0x100000;R=B+0x60000;K=B+0x2c000;PORT=B+0xc0000;REP=B+0x80070;TS=B+0xa8040;KS=B+0x54000;RS=B+0x54100;SPACE=B+0xdd000;TABLE=0x400000100000;CLIENT=B+0x987c0;BSD=CLIENT-0x7c0;OWNER=B+0x70000;TASKREC=B+0x5c000;KMSG=B+0xd0000;MAP=B+0x78000;PSP=B+0xe8000;HALT=B+0xe0000;ARRAY=0xfffffe000caeb480
CONFIGS=[{'case':'unlinked','constructor_case':1},{'case':'first_link','constructor_case':1},{'case':'shared_link','constructor_case':1},{'case':'bootstrap_link_reset','constructor_case':17},{'case':'unbind','constructor_case':1},{'case':'replace','constructor_case':1}]
def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def put(b,o,n,v):b[o:o+n]=v.to_bytes(n,'little')
def gbytes(im,rows,a,n):
 if TABLE<=a<a+n<=TABLE+4096:b=bytearray(n)
 else:
  b=bytearray();pos=a
  while pos<a+n:pg=pos&~4095;take=min(a+n-pos,4096-(pos-pg));b+=im.logical_page(pg)[pos-pg:pos-pg+take];pos+=take
 for e in rows:
  at=int(e['address'],16);raw=bytes.fromhex(e['bytes_hex']);lo=max(a,at);hi=min(a+n,at+len(raw))
  if lo<hi:b[lo-a:hi-a]=raw[lo-at:hi-at]
 return bytes(b)
def gput(rows,a,b):
 rows=[dict(e)for e in rows];found=False
 for e in rows:
  at=int(e['address'],16);raw=bytearray.fromhex(e['bytes_hex']);lo=max(a,at);hi=min(a+len(b),at+len(raw))
  if lo<hi:raw[lo-at:hi-at]=b[lo-a:hi-a];e['bytes_hex']=raw.hex()
  found|=at==a and len(raw)==len(b)
 if not found:rows.append({'address':hex(a),'bytes_hex':b.hex()})
 return rows
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());prior=json.loads((ROOT/'kernel_reply_namespace_profiles.json').read_text());old=json.loads((ROOT/'kernel_receive_copyout_profiles.json').read_text());ctors=json.loads((ROOT/'kext_constructor_request_profiles.json').read_text());counts=Counter();totals=Counter();proofs=[];summaries=[]
 for obj,script in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 assert src['kernel_sha256']==im.k.sha256 and len(src['functions'])==110 and sum(len(f['instructions'])for f in src['functions'])==14746
 for f in src['functions']:
  a=int(f['start'],16);raw=im.k.read(a,int(f['end'],16)-a);assert raw.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==f['instructions'];counts['original_complete_functions_recaptured']+=1
 for e in src['special_reply_instruction_roles'].values():
  a=int(e['pc'],16);i=next(im.k.cs.disasm(im.k.read(a,4),a));assert e=={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};counts['special_reply_instruction_roles_recaptured']+=1
 scan=src['reply_space_reference_scan'];assert scan['instruction_words']==2540432 and len(scan['hits'])==5 and scan['arbitrary_indirect_writer_completeness_established']is False
 for e in scan['hits']:
  a=int(e['pc'],16);raw=im.k.read(a,100);assert raw.hex()==e['bytes100_hex']and[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]==e['instructions'];counts['kernel_reply_space_reference_windows_recaptured']+=1
 assert [e['pc']for e in scan['hits']]==['0xfffffe000bccfa90','0xfffffe000bccfbe0','0xfffffe000bcf5d70','0xfffffe000bcf8e6c','0xfffffe000c629824']
 for e in src['bootstrap_file_cells']:assert im.k.read(int(e['address'],16),len(e['bytes_hex'])//2).hex()==e['bytes_hex']
 assert im.k.read(0xfffffe0007e63348,8)==bytes(8);counts['original_file_zero_and_bootstrap_constants_checked']=1
 assert len(src['special_zone_entries'])==3 and len(prof['zone_producers'])==3
 for e in src['special_zone_entries']:
  at=int(e['entry_address'],16);a=int(e['specification_address'],16);assert im.k.read(at,24).hex()==e['entry_bytes24_hex']and im.k.read(a,48).hex()==e['specification_bytes48_hex']and im.pointer(at+8)==e['callback_pointer']and im.pointer(at+16)==e['argument_pointer']and im.pointer(a+8)==e['name_pointer'];counts['selected_startup_records_specs_and_fixups_recaptured']+=1
 for j,(z,name,ident,base)in enumerate(zip(prof['zone_producers'],['ipc ports','turnstiles','ipc spaces'],[22,28,40],[B+0x40000,B+0x44000,B+0x48000],strict=True)):
  spec=next(e for e in src['special_zone_entries']if e['name']==name);size=spec['requested_size_u64'];zone=ARRAY+192*ident;cache=ident==22;want=bytearray(192);recip=((1<<32)+size-1)//size
  for o,n,v in[(0,8,zone),(8,8,base),(16,8,int(spec['name_pointer']['target'],16)),(0x28,4,recip),(0x30,4,recip),(0x34,2,size),(0x36,2,16384%size),(0x38,2,1),(0x3a,2,16384//size)]:put(want,o,n,v)
  if cache:put(want,0x40,8,base+0x1000);put(want,0x7e,2,0x100000//(16*size))
  if ident==40:
   for o,n,v in[(0x3c,4,0x400),(0x58,8,zone+0x50),(0x60,4,0x144),(0x80,4,0x144),(0x84,4,0xffffffff)]:put(want,o,n,v)
  assert z['configuration']=={'identifier':spec['identifier_u16'],'storage_base':base}and z['identifier']==ident and z['requested_identifier_u16']==spec['identifier_u16']and z['zone_address']==hex(zone)and z['final_zone192_hex']==want.hex()and z['boundary']['kind']=='startup_callback_returned'and all(z[k]is False for k in FLAGS);counts['independent_complete_zone_records_and_geometry_checked']+=1
  expected_regions=[(base,bytes(32))]
  if cache:
   cb=bytearray(64);put(cb,0,4,0x144);put(cb,8,8,base+0x2010);put(cb,16,8,base+0x2110);put(cb,0x28,8,base+0x1020);expected_regions.extend([(base+0x1000,bytes(cb)),(base+0x2000,bytes(144)),(base+0x2100,bytes(144))])
  assert [(int(e['address'],16),bytes.fromhex(e['bytes_hex']))for e in z['source_private_regions']]==expected_regions and len(z['raw_magazine_returns'])==2*int(cache);counts['source_statistics_cache_magazine_records_and_disjoint_regions_checked']+=1
  gm=z['final_image_globals'];count=next(e for e in gm if e['address']=='0xfffffe000caeb45a');assert count['bytes_hex']==('2900'if ident==40 else'2800')
  if ident==40:assert z['published_space_zone_pointer']==hex(zone)and next(e for e in gm if e['address']=='0xfffffe0007e5c470')['bytes_hex']==struct.pack('<Q',zone).hex();counts['original_dynamic_zone_selection_and_publication_checked']+=1
  else:assert z['published_space_zone_pointer']is None
  totals.update(ZoneReplay(im,z).run())
 freshparent=NamespaceReplay(im,prior['cases'][1]).run();freshctors={str(j):ConstructorReplay(im,ctors['cases'][j]).run()for j in[1,17]};counts['fresh_parent_destination_send_reference_producer_replayed']=1;counts['fresh_original_kext_packet_producers_replayed']=2
 a=BitVec('arena_pointer_a64',64);b=BitVec('arena_pointer_b64',64);ref=BitVec('object_references32',32);primary=BitVec('turnstile_primary32',32);flags=BitVec('port_flags32',32);state=BitVec('new_state32',32);changed=(flags&0xffff8fff)|((state&7)<<12)
 queries=[('arena_type_metadata_cells_equal_exactly_within_16KiB_pages',And(UGE(a,B),ULT(a,B+SIZE),UGE(b,B),ULT(b,B+SIZE)),(LShR(a,10)&0xffffffff0)==(LShR(b,10)&0xffffffff0),(a&0xffffffffffffc000)==(b&0xffffffffffffc000)),('paired_destination_and_primary_holds_balance_without_wrap',And(UGE(ref,1),ULE(ref,0xffffffd),UGE(primary,1),ULE(primary,0xfffffffe)),And((ref+1)-1==ref,(primary+1)-1==primary),True),('sync_state_update_preserves_other_fields_and_bootstrap_flag',ULE(state,7),And((changed&0xffff8fff)==(flags&0xffff8fff),(changed&0x8000)==(flags&0x8000)),True)]
 for label,domain,left,right in queries:
  s=Solver();s.add(domain,left!=right);assert s.check()==unsat;proofs.append({'name':label,'domain':str(domain),'query':s.sexpr(),'result':'unsat'});counts['bounded_scalar_proofs_unsat']+=1;print(json.dumps({'proof':label,'result':'unsat'}),flush=True)
 assert len(prof['cases'])==35;seedram=decode(prior['cases'][1]['final_private_RAM']);seedglobals=prior['cases'][1]['final_image_globals'];raw=decode(old['consumers'][0]['final_private_RAM'])[0xd0000:0xd0100];rowidx=0;zones=prof['zone_producers']
 for family,c0 in enumerate(CONFIGS):
  c={'index':2,'old_bits':0,**c0};tag=c['case'];ram=seedram;gl=[dict(e)for e in seedglobals];origin={'path':'kernel_reply_namespace_profiles.json','case':1};packet0=bytes.fromhex(ctors['cases'][c['constructor_case']]['message88_hex']);packet=bytearray(packet0);struct.pack_into('<IIQQ',packet,0,0x80001211,88,PORT,REP);kinds=['space_bootstrap','create','make_send_once']
  if tag=='shared_link':kinds.append('prepare_outer_hold')
  if tag!='unlinked':kinds.append('link')
  kinds.append('header')
  if tag=='shared_link':kinds.append('drop_outer_hold')
  if tag=='bootstrap_link_reset':kinds+=['reply_lock','allow_linkage']
  if tag in ['unbind','replace']:kinds.append(tag)
  for kind in kinds:
   r=prof['cases'][rowidx];current=R if kind=='header'else K;assert r['family']==family and r['kind']==kind and r['configuration']==c and r['current_thread']==hex(current)and decode(r['initial_state_transfer'])==ram and all(r[k]is False for k in FLAGS)
   for key,v in origin.items():assert r['initial_state_transfer'][key]==v
   counts['exact_component_full_RAM_origins_checked']+=1;initial=bytearray(ram);plan=[];gplan=[];steps=[];regional=[];zonerecords=[]
   if kind=='space_bootstrap':
    meta=val(gbytes(im,gl,0xfffffe0007e66f00,8),0);plan=[(KS,bytes(128)),(RS,bytes(128)),(TS,bytes(96)),(TS+96,b'\xa5'),(meta+((TS>>10)&0xffffffff0),struct.pack('<H',28)),(BSD,bytes(0xe90)),(OWNER+0x28,struct.pack('<Q',CLIENT)),(SPACE+0x50,struct.pack('<Q',CLIENT)),(CLIENT+0x318,struct.pack('<Q',SPACE)),(meta+((BSD>>10)&0xffffffff0),struct.pack('<H',26)),(meta+((KS>>10)&0xffffffff0),struct.pack('<H',40)),(meta+((SPACE>>10)&0xffffffff0),struct.pack('<H',40)),(BSD+0x60,struct.pack('<I',4242)),(TASKREC,bytes(32)),(TASKREC+0x18,struct.pack('<I',77)),(CLIENT+0x320,struct.pack('<Q',TASKREC)),(CLIENT+0x6c8,struct.pack('<I',int(tag!='shared_link')))]
    steps=[('private',a,b)for a,b in plan]
    for j,z in enumerate(zones):
     for e in z['source_private_regions']:
      a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);plan.append((a,b));steps.append(('private',a,b));regional.append({'producer':j,**e})
     a=int(z['zone_address'],16);b=bytes.fromhex(z['final_zone192_hex']);gplan.append((a,b));steps.append(('image_global',a,b));zonerecords.append({'producer':j,'address':hex(a),'bytes192_hex':b.hex()})
    gplan.extend([(0xfffffe0007e5c470,struct.pack('<Q',ARRAY+192*40)),(0xfffffe0007e63348,bytes(8))]);steps.extend(('image_global',a,b)for a,b in gplan[-2:])
   if kind=='header':
    b=bytearray(raw);b[0x40:0x98]=packet;plan=[(KMSG,bytes(b))];steps=[('private',KMSG,bytes(b))];assert r['packet_import']=={'constructor_case':c['constructor_case'],'constructor_message88_hex':packet0.hex(),'internal_message88_hex':packet.hex(),'source_kmsg_container256_hex':raw.hex(),'native_transport_continuity_established':False};counts['original_packet_fields_and_declared_internal_header_imports_checked']+=1
   else:assert r['packet_import']is None
   assert r['zone_record_imports']==zonerecords and r['zone_private_record_imports']==regional and r['initial_private_fixtures']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in plan]and len(r['input_overlays'])==len(plan)+len(gplan)
   assert len(steps)==len(r['input_overlays'])
   for(space,a,b),e in zip(steps,r['input_overlays'],strict=True):
    before=initial[a-B:a-B+len(b)]if space=='private'else gbytes(im,gl,a,len(b));assert e['address']==hex(a)and e['before_hex']==before.hex()and e['after_hex']==b.hex()and e['space']==space
    if space=='private':initial[a-B:a-B+len(b)]=b;counts['private_fixture_or_source_region_before_images_checked']+=1
    else:gl=gput(gl,a,b);counts['source_zone_and_publication_global_before_images_checked']+=1
   assert r['initial_image_fixtures']==gl;counts['canonical_overlapping_global_observation_epochs_checked']+=1
   entry,args={'space_bootstrap':(0xfffffe000c629780,[]),'create':(0xfffffe000bcf8e14,[]),'replace':(0xfffffe000bcf8e14,[]),'make_send_once':(0xfffffe000bcd0694,[REP]),'prepare_outer_hold':(0xfffffe000bcced98,[PORT]),'link':(0xfffffe000bccef30,[REP,PORT,int(tag=='bootstrap_link_reset')]),'header':(0xfffffe000bcc4e98,[KMSG,SPACE,MAP,0x07000002]),'drop_outer_hold':(0xfffffe000bcceadc,[PORT]),'reply_lock':(0xfffffe000bccc128,[REP]),'allow_linkage':(0xfffffe000bcce5b8,[REP,0,1,0]),'unbind':(0xfffffe000bcf837c,[K])}[kind];regs=['0x0']*31
   for j,v in enumerate(args):regs[j]=hex(v)
   regs[30]=hex(HALT);assert r['entry_PC']==hex(entry)and r['entry_SP']==hex(PSP)and r['entry_registers31']==regs and r['entry_DAIF_mask']=='0x200';counts['explicit_call_thread_and_entry_ABIs_checked']+=1
   wp=bytearray(initial[PORT-B:PORT-B+144]);wr=bytearray(initial[REP-B:REP-B+144]);wt=bytearray(initial[TS-B:TS-B+96]);wk=bytearray(initial[K-B:K-B+1536]);wrecv=bytearray(initial[R-B:R-B+1536]);wks=bytearray(initial[KS-B:KS-B+128]);wrs=bytearray(initial[RS-B:RS-B+128]);ws=bytearray(initial[SPACE-B:SPACE-B+128]);wh=bytearray(initial[KMSG-B+0x40:KMSG-B+0x98]);we=bytearray(gbytes(im,gl,TABLE+48,24));nest=0;rawalloc=[];retire=False
   if kind=='space_bootstrap':
    for dest in[wks,wrs]:
     dest[:]=bytes(128);dest[:8]=im.k.read(0xfffffe000700dc58,8);put(dest,8,4,0x144);dest[12:20]=im.k.read(0xfffffe000700dc60,8);put(dest,0x58,8,16);put(dest,0x68,4,3)
    gl=gput(gl,0xfffffe0007e62b68,struct.pack('<Q',KS));gl=gput(gl,0xfffffe0007e63348,struct.pack('<Q',RS));rawalloc=[(ARRAY+192*40,B+0x48000,KS,128),(ARRAY+192*40,B+0x48000,RS,128)];assert r['boundary']['kind']=='before_unrelated_bootstrap_kernel_object'and r['boundary']['pc']=='0xfffffe000c62982c';counts['original_two_special_space_records_and_publications_checked']+=1
   elif kind=='create':
    wr=bytearray(144)
    for o,n,v in[(0,4,0x20b),(4,4,1),(0x10,4,0x000c000b),(0x14,4,0x01010144),(0x34,4,1),(0x3a,2,5),(0x40,8,K),(0x48,8,RS)]:put(wr,o,n,v)
    put(wk,0x3f0,8,REP);rawalloc=[(ARRAY+192*22,B+0x40000,REP,144)];assert r['boundary']['kind']=='original_component_returned'and r['boundary']['registers31'][0]=='0x0';counts['original_bound_kernel_reply_port_records_and_creator_return_checked']+=1
    sf=next(e for e in r['special_reply_frames']if e['pc']=='0xfffffe000bcf8ea8');uf=next(e for e in r['special_reply_frames']if e['pc']=='0xfffffe000bcf8ef4');assert val(bytes.fromhex(sf['reply144_hex']),4,4)==1 and val(bytes.fromhex(uf['reply144_hex']),4,4)==1 and val(bytes.fromhex(uf['kernel_thread1536_hex']),0x3f0)==REP;counts['source_binding_retain_release_and_owner_publication_frames_checked']+=1
   elif kind=='make_send_once':put(wr,4,4,2);put(wr,0x8c,4,1);put(wr,0x14,4,0x02020144)
   elif kind in ['prepare_outer_hold','link']:
    fresh=val(wp,0x70)==0;put(wp,0x14,4,val(wp,0x14,4)+(0x02020000 if fresh else 0x01010000));put(wp,0x70,8,TS)
    if fresh:
     wt=bytearray(96)
     for o,n,v in[(0,4,2),(4,4,0x02020144),(0x48,8,PORT),(0x50,4,1),(0x54,4,0x204),(0x58,4,1)]:put(wt,o,n,v)
     rawalloc=[(ARRAY+192*28,B+0x44000,TS,96)]
    else:put(wt,0x58,4,val(wt,0x58,4)+1)
    if kind=='link':put(wp,4,4,4);put(wr,0x14,4,0x03030144);put(wr,0x10,4,0x000c100b|(0x8000 if tag=='bootstrap_link_reset'else 0));put(wr,0x58,8,PORT);counts['original_special_reply_link_and_separate_holds_checked']+=1
    else:counts['original_outer_send_turnstile_hold_producer_checked']+=1
   elif kind=='header':
    linked=tag!='unlinked';outer=tag=='shared_link';put(wp,4,4,2);put(wp,0x88,4,1);put(wp,0x14,4,0x0b0b0144 if not linked else 0x0f0f0144 if outer else 0x0e0e0144);put(wr,0x14,4,0x04040144 if linked else 0x03030144)
    if linked:
     put(wr,0x10,4,0x000c400b|(0x8000 if tag=='bootstrap_link_reset'else 0));put(wr,0x58,8,0);put(wr,0x60,4,77 if outer else 4242)
     if outer:put(wt,0x58,4,1)
     else:wt=bytearray(96);put(wp,0x70,8,0);retire=True
     hasproc=any(e['pc']=='0xfffffe000c2ba130'for e in r['source_visits']);assert hasproc==(not outer);counts['original_BSD_proc_or_task_record_diagnostic_PID_paths_checked']+=1
    put(ws,8,4,0x01010000);put(ws,0x18,4,0);put(ws,0x70,4,2);put(ws,0x74,4,2);put(we,0,8,REP);typeflags=val(im.k.read(0xfffffe0007e62b70+11*40+8,2),0,2);entrybits=0x04040001|(0 if typeflags&0x200 else 0x800000);put(we,8,4,entrybits);put(we,12,4,0);tb=bytearray(gbytes(im,gl,TABLE,4096));put(tb,12,4,0);tb[48:72]=we;gl=gput(gl,TABLE,bytes(tb));wh=bytearray(struct.pack('<IIQQII',0x80001112,88,0x207,0x303,0,val(packet,28,4))+packet[32:]);assert r['boundary']['kind']=='before_original_descriptor_copyout'and r['boundary']['pc']=='0xfffffe000bcc5564';counts['actual_kernel_special_reply_namespace_header_publications_checked']+=1
   elif kind=='drop_outer_hold':put(wp,0x14,4,0x10100144);put(wp,0x70,8,0);wt=bytearray(96);retire=True;counts['original_last_outer_hold_completion_checked']+=1
   elif kind=='reply_lock':put(wr,0x14,4,0x05040144);put(wk,0x1c8,4,1);nest=1
   elif kind=='allow_linkage':put(wr,0x14,4,0x05050144);put(wr,0x10,4,0x000c800b);put(wr,0x60,4,0);put(wk,0x1c8,4,0);counts['original_allow_linkage_reset_with_owner_and_bootstrap_preserved_checked']+=1
   elif kind in ['unbind','replace']:put(wr,0x14,4,0x06050144);put(wr,0x40,8,0);put(wk,0x3f0,8,0);put(wk,0x1c8,4,1);nest=1;assert r['boundary']['kind']=='before_original_bound_port_destruction'and r['boundary']['pc']=='0xfffffe000bccdbb4'and r['boundary']['registers31'][0]==hex(REP);counts['original_unbind_or_replacement_owner_clear_and_held_destroy_prefixes_checked']+=1
   assert r['final_port144_hex']==wp.hex()and r['final_reply144_hex']==wr.hex()and r['final_send_turnstile96_hex']==wt.hex()and r['final_kernel_thread1536_hex']==wk.hex()and r['final_receiver1536_hex']==wrecv.hex()and r['final_kernel_space128_hex']==wks.hex()and r['final_reply_space128_hex']==wrs.hex()and r['final_space128_hex']==ws.hex()and r['final_entry24_hex']==we.hex()and r['final_header88_hex']==wh.hex()and r['final_image_globals']==gl and r['final_current_nesting']==nest and r['final_send_turnstile_guard_hex']=='a5';counts['independent_complete_space_port_thread_turnstile_entry_header_and_global_oracles_checked']+=1
   assert len(r['raw_storage_contracts'])==len(rawalloc)
   for e,(zone,stats,ptr,extent)in zip(r['raw_storage_contracts'],rawalloc,strict=True):assert e['arguments4'][:3]==[hex(zone),hex(stats),'0x8004']and e['returned_pointer']==hex(ptr)and e['object_before_hex']=='00'*extent;counts['source_raw_storage_ABIs_and_zeroed_before_records_checked']+=1
   expectedmodels=Counter()
   if kind=='space_bootstrap':expectedmodels['declared_zeroed_raw_special_space_storage']=2
   elif kind=='create':expectedmodels['declared_zeroed_raw_kernel_reply_port_storage']=1
   elif rawalloc:expectedmodels['declared_zeroed_raw_send_turnstile_storage']=1
   if kind=='header':expectedmodels['opaque_keyed_hash_result']=2
   if retire:expectedmodels['declared_raw_send_turnstile_retirement']=1
   assert Counter(m['symbol']for m in r['API_models'])==expectedmodels
   for m in r['API_models']:
    assert m['native_effects_executed']is False
    if m['symbol']=='opaque_keyed_hash_result':assert m['return_value']=='0x123456789abcdef0'
   counts['only_declared_raw_storage_hash_and_retirement_models_checked']+=1
   assert len(r['raw_retirement_contracts'])==int(retire)
   if retire:
    e=r['raw_retirement_contracts'][0];assert e['arguments4']==[hex(ARRAY+192*28),hex(B+0x44000),hex(TS),'0x60']and e['turnstile96_hex']=='00'*96 and e['guard_byte_hex']=='a5'
    zero=[w for w in r['source_writes']if 0xfffffe000c6480c0<=int(w['pc'],16)<0xfffffe000c648170 and TS<=int(w['address'],16)<TS+96];covered=set()
    for w in zero:
     a=int(w['address'],16);assert TS<=a<a+w['size_bytes']<=TS+96 and w['after_hex']=='00'*w['size_bytes']and w['source_visit_index']<e['before_source_visit_index'];covered.update(range(a,a+w['size_bytes']))
    assert covered==set(range(TS,TS+96))and any(v['pc']=='0xfffffe000bd6d488'for v in r['source_visits'])and any(v['pc']=='0xfffffe000bd0aa54'for v in r['source_visits']);counts['original_turnstile_lock_destruction_complete_zeroing_and_retirement_order_checked']+=1
   for v in r['source_visits']:assert im.k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['every_main_original_instruction_recaptured']+=1
   totals.update(Replay(im,r).run());ram=decode(r['final_private_RAM']);origin={'path':P+'_profiles.json','case':rowidx};print(json.dumps({'case':rowidx,'family':family,'kind':kind,'original_replay':'pass','boundary':r['boundary']['kind']}),flush=True);rowidx+=1
  end=prof['cases'][rowidx-1];rb=bytes.fromhex(end['final_reply144_hex']);summaries.append({'family':family,'configuration':c0,'boundary':end['boundary']['kind'],'bound_port':hex(val(bytes.fromhex(end['final_kernel_thread1536_hex']),0x3f0)),'owner_thread':hex(val(rb,0x40)),'sync_state':val(rb,0x10,4)>>12&7,'bootstrap_bit':bool(val(rb,0x10,4)&0x8000),'diagnostic_word':val(rb,0x60,4),'reply_refs':val(rb,4,4),'send_once_rights':val(rb,0x8c,4),'turnstile_zeroed':end['final_send_turnstile96_hex']=='00'*96})
 assert rowidx==35
 # The geometry check is an arithmetic/provenance check, not native allocation validity.
 for addr,j in[(REP,0),(TS,1),(KS,2),(RS,2)]:
  z=bytes.fromhex(zones[j]['final_zone192_hex']);offset=(addr&0x3fff)-val(z,0x36,2);reciprocal=val(z,0x30,4);assert 0<=offset<16384 and(offset*reciprocal)&0xffffffff<reciprocal;counts['source_zone_selected_object_geometry_checks']+=1
 metadata_cells={label:(a>>10)&0xffffffff0 for label,a in [('receiver_owner',OWNER),('BSD_wrapper',BSD),('special_reply',REP),('send_turnstile',TS),('special_spaces',KS)]};assert len(set(metadata_cells.values()))==len(metadata_cells)and 0x7c0+0x6c8+4<=0xe90;counts['disjoint_typed_object_metadata_cells_and_embedded_task_extent_checked']=1
 counts.update(cases=35,zone_producers=3,functions=110,captured_instructions=14746)
 deps=[P+'_source.json',P+'_profiles.json','kernel_reply_namespace_profiles.json','kernel_receive_copyout_profiles.json','kext_constructor_request_profiles.json','replay_'+P+'.py','replay_kernel_reply_namespace.py','replay_kernel_zone_startup.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','replay_kext_constructor_request.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_parent_replay':freshparent,'fresh_kext_packet_producer_replays':freshctors,'proofs':proofs,'family_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
