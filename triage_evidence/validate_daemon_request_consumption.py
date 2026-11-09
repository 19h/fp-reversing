#!/usr/bin/env python3
"""Independent source, kernel-producer replay, daemon replay and packet/ABI oracles.
O(source+visits+RAM+journals+fixups), O(image+RAM+journals). Native execution,
framework transfer and port-to-daemon pairing remain unproved.
"""
import json,struct
from collections import Counter
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,verify_original_fixups
from recover_daemon_request_consumption import P,FLAGS,sha,build
from replay_daemon_request_consumption import Replay
from replay_kernel_request_delivery import Replay as KernelReplay
from replay_rpc502_vm_handoff import decode
from kernel_vm_mig_tools import Image as KernelImage
from resolve_kernel_collection_interfaces import commands
B=0x6500000000;USER=B+0x1000;OOL=B+0x4000;REPLY=B+0x80000
def main():
 source=json.loads((ROOT/(P+'_source.json')).read_text());profiles=json.loads((ROOT/(P+'_profiles.json')).read_text());kernel=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text());counts=Counter();totals=Counter();kt=Counter();summary=[];slots=set()
 assert source==build();counts['original_ranges_recaptured']=len(source['ranges']);counts['original_instructions_recaptured']=sum(len(r['instructions'])for r in source['ranges'])
 for obj,script in [(source,'recover_'+P+'.py'),(profiles,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 assert len(profiles['cases'])==len(kernel['cases'])==8;im=KernelImage()
 for j,(r,k)in enumerate(zip(profiles['cases'],kernel['cases'],strict=True)):
  assert r['kernel_case_index']==j and r['configuration']==k['configuration'];ram=decode(k['final_private_RAM']);user=bytes.fromhex(k['final_user8192_hex']);ool=bytes.fromhex(k['final_OOL16384_hex']);assert ram[0x1000:0x1000+8192]==user and ram[0x4000:0x4000+16384]==ool
  assert k['boundary']['kind']=='receive_frontend_returned'and k['boundary']['registers31'][0]=='0x0';kt.update(KernelReplay(im,k).run());counts['fresh_kernel_delivery_cases_replayed']+=1;counts['exact_cross_image_buffer_bytes_checked']+=len(user)+len(ool)
  producer=k['configuration']['producer'];cap=k['configuration']['capacity'];mid=502 if producer<2 else 700;service=0x303 if mid==502 else 0x403;trailer=cap-80
  assert struct.unpack_from('<6I',user)==(0x80001112,80,0x207,service,0,mid)and struct.unpack_from('<I',user,24)[0]==1 and struct.unpack_from('<Q',user,28)[0]==OOL and struct.unpack_from('<II',user,36)==(0x01000101,29)and user[44:52]==bytes.fromhex('0000000001000000')and struct.unpack_from('<I3Q',user,52)==(29,0x100000c,0,1)and struct.unpack_from('<II',user,80)==(0,trailer)
  assert ool[:29]==bytes(0x21+x%90 for x in range(28))+b'\0'and user[cap:]==b'\xa5'*(8192-cap);counts['complete_normal_request_schema_and_payload_checked']+=1
  after=bytearray(user);reply=bytearray(b'\xa5'*384);kind=r['boundary']['kind'];visits={v['pc']for v in r['source_visits']}
  if mid==700:
   assert kind=='callback_returned'and not r['imports']and '0x100005274'not in visits and '0x1000050c8'not in visits;counts['RPC700_callback_exclusions_checked']+=1
  else:
   assert r['imports'][0]['name']=='libSystem/_malloc'and r['imports'][0]['before']['registers31'][0]=='0x180';struct.pack_into('<6I',reply,0,18,36,0x207,0,0,602)
   if trailer==8:
    assert kind=='before_request_destroy'and len(r['imports'])==2 and r['imports'][1]['before']['registers31'][0]==hex(USER);struct.pack_into('<I',after,8,0);reply[24:32]=bytes.fromhex('0000000001000000');struct.pack_into('<i',reply,32,-309);assert '0x100422d48'not in visits and not any(v['pc']=='0x1000051f8'for v in r['source_visits']);counts['minimal_trailer_error_and_reply_right_preservation_checked']+=1
   else:
    assert trailer==68 and kind=='before_application'and len(r['imports'])==1;struct.pack_into('<I',reply,36,0x01000101);struct.pack_into('<I',reply,52,0x01000101)
    args=r['application_arguments8'];assert args[:6]==[hex(service),hex(OOL),'0x1d','0x100000c','0x0','0x1']and int(args[6],16)==int(r['boundary']['SP'],16)+0x30 and args[7]==hex(REPLY+0x44);assert r['application_stack_arguments5']==[hex(REPLY+x)for x in (0xcc,0x1c,0x178,0x2c,0x17c)]and r['application_audit32_hex']==user[100:132].hex()=='00'*32
    assert '0x1000051cc'in visits and '0x1000051d0'in visits and '0x1000051f8'in visits;counts['extended_trailer_complete_application_ABI_and_audit_copy_checked']+=1
  assert r['final_user8192_hex']==after.hex()and r['final_OOL16384_hex']==ool.hex()and r['reply384_hex']==reply.hex();counts['complete_message_OOL_and_reply_oracles_checked']+=1
  for e in r['source_reads']:
   a=int(e['address'],16);slots.update(x for x in range(a,a+e['size_bytes'])if x in FIXUPS)
  totals.update(Replay(r,k,source).run());summary.append({'kernel_case':j,'producer':producer,'request_id':mid,'service_name_u32':hex(service),'inline_bytes':80,'trailer_bytes':trailer,'OOL_bytes':29,'boundary':kind,'source_visits':len(r['source_visits'])});print(json.dumps(summary[-1]),flush=True)
 auth_slots={a for a in slots if FIXUPS[a]['kind']!='bind'};fix=verify_original_fixups(auth_slots)
 # The frozen verifier intentionally restricts binds to authenticated pointers.
 # Independently decode the original unauthenticated format12 NDR data bind.
 for a in sorted(slots-auth_slots):
  assert FIXUPS[a]['target']=='libSystem/_NDR_record';data=IMAGE.data;at=next(o for o,c,n in commands(data,0)if c==0x80000034);fo,_=struct.unpack_from('<II',data,at+8);version,_,imports,symbols,count,fmt,symfmt=struct.unpack_from('<7I',data,fo);assert(version,fmt,symfmt)==(0,2,0)
  word=struct.unpack('<Q',IMAGE.read(a,8))[0];ordinal=word&0xffffff;assert word>>62==1 and ordinal<count and((word>>32)&0x7ffff)==0;packed,addend=struct.unpack_from('<Ii',data,fo+imports+ordinal*8);start=fo+symbols+(packed>>9);name=data[start:data.index(0,start)].decode();assert name=='_NDR_record'and addend==0
  fix['records'].append({'address':hex(a),'word':hex(word),'pointer_format':12,'authenticated':False,'bind':True,'import_ordinal':ordinal,'library_ordinal':packed&255,'import_name':name,'import_addend':0,'pointer_addend':0})
 counts['original_used_fixup_words_checked']=len(fix['records']);counts['cases']=8
 assert totals['original_instruction_visits_checked']==2478 and totals['final_boundaries_checked']==8 and totals['whole_private_RAM_bytes_checked']==12582912 and kt['source_visits_checked']==20700
 assert counts['RPC700_callback_exclusions_checked']==4 and counts['minimal_trailer_error_and_reply_right_preservation_checked']==2 and counts['extended_trailer_complete_application_ABI_and_audit_copy_checked']==2
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','daemon_rpc502_probe.py','daemon_receive_tools.py','kernel_request_delivery_profiles.json','kernel_request_delivery_checks.json','replay_kernel_request_delivery.py','replay_rpc502_vm_handoff.py']},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'fresh_kernel_delivery_replay':dict(kt),'used_original_fixup_checks':fix,'case_summaries':summary,'all_checks_pass':True,**FLAGS};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(counts),'replay':dict(totals),'kernel':dict(kt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
