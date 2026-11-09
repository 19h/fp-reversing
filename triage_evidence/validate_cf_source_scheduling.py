#!/usr/bin/env python3
"""Recapture original scheduling source and independently verify all11 cases.
O(source/cache bytes+visits+RAM+journals), O(image+RAM+journals). Lower
collections/Mach traps and selected kernel-packet port-set handoff are models.
"""
import copy,json,struct
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,CS
from recover_cf_source_scheduling import P,FLAGS,sha,build,ADD,GETPORT,DSET,DGET,FIND,TYPE_TRAP,INSERT_TRAP
from recover_cf_receive import RUN,DO_SOURCE
from replay_cf_source_scheduling import Replay,B,USER,OOL,RL,MODE,SRC,OBJ,DICT,SET0,SET1,BAG,PSET,TASK,NAME
from replay_kernel_request_delivery import Replay as KernelReplay
from kernel_vm_mig_tools import Image
def get(n):return json.loads((ROOT/n).read_text())
def main():
 s=get(P+'_source.json');p=get(P+'_profiles.json');prior=get('cf_runloop_handoff_profiles.json');old=get('cf_daemon_request_profiles.json');assert s==build();counts=Counter();rt=Counter();kt=Counter();rows=[]
 sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/CoreFoundation.framework/Headers/CFRunLoop.h').resolve();header=sdk.read_text();assert 'CF_EXPORT void CFRunLoopAddSource(CFRunLoopRef rl, CFRunLoopSourceRef source, CFRunLoopMode mode);'in header and 'kCFRunLoopRunHandledSource = 4'in header;sdk_evidence={'path':str(sdk),'sha256':sha(sdk),'AddSource_return_type':'void','SDK_handled_source_enum_value':4,'exact_cache_build_correspondence_established':False}
 for obj,script in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 fs={int(f['start'],16):f for f in s['CF_functions']};assert len(fs)==28 and len(s['import_stubs'])==10 and len(s['cache_files'])==9 and p['kernel_cases']==prior['kernel_cases']and len(p['cases'])==11
 assert fs[GETPORT]['instructions']==[{'ea':'0x1847e8924','mnemonic':'ldr','operands':'w0, [x0, #0x14]'},{'ea':'0x1847e8928','mnemonic':'ret','operands':''}];ins={int(i['ea'],16):i for i in fs[ADD]['instructions']};assert ins[0x18472dc00]['operands']=='#0x1846dcc44'and ins[0x18472dc04]['operands']=='w2, [x22, #0x88]'and ins[0x18472dc18]['operands']=='#0x188085b80'and ins[0x18472dc1c]['mnemonic']=='add';counts.update({'complete_cache_functions_recaptured':28,'captured_cache_instructions':sum(len(f['instructions'])for f in fs.values())+40,'complete_AddSource_body_instructions':len(fs[ADD]['instructions']),'original_import_stubs_checked':10,'cache_files_hashed':9,'original_getPort_and_dictionary_member_call_order_checks':1})
 assert s['extra_pointer_fixups'][-1]['address']=='0x1e01c8b30'and s['extra_pointer_fixups'][-1]['target']=='0x1ed83e960';counts['original_task_global_binding_checked']=1;im=Image()
 hs={int(e['address'],16):e for e in s['scheduling_helper_boundaries']}
 for a,selector in((TYPE_TRAP,'x16, #-0x4c'),(INSERT_TRAP,'x16, #-0x16')):
  decoded=list(CS.disasm(bytes.fromhex(hs[a]['original_bytes16_hex']),a));assert[(i.mnemonic,i.op_str)for i in decoded[:3]]==[('mov',selector),('svc','#0x80'),('ret','')];counts['original_Mach_trap_instruction_roles_checked']+=3
 for k in p['kernel_cases']:kt.update(KernelReplay(im,k).run())
 for case_index,r in enumerate(p['cases']):
  c=r['configuration'];j=c['kernel_case'];k=p['kernel_cases'][j];rt.update(Replay(r,k,s).run());st=r['final_model_state'];F=r['scheduling_frames'];model=r['scheduling_models'];port=0 if c['zero_port']else int(k['receive_name'],16);dic=[e for e in model if e['pc']=='0x1846dcd84'];member=[e for e in model if e['pc']==hex(INSERT_TRAP)];types=[e for e in model if e['pc']==hex(TYPE_TRAP)];bags=[e for e in model if e['pc']=='0x1846fb960'and e['before']['registers31'][0]==hex(BAG)]
  assert all(e['before']['registers31'][:2]==[hex(TASK),hex(port)]for e in types)and len(types)==c['repeat']and all(e['before']['registers31'][:3]==[hex(TASK),hex(port),hex(PSET)]for e in member)
  first=next(f for f in F if f['pc']==hex(ADD));assert first['registers31'][:3]==[hex(RL),hex(SRC),hex(NAME)]and first['model_state']=={'dictionary':{},'collections':{hex(SET0):[],hex(SET1):[],hex(BAG):[]},'members':[],'bag_counts':{}};obj=bytes.fromhex(first['CF_object160_hex']);source=bytes.fromhex(first['source256_hex']);mode=bytes.fromhex(first['mode512_hex']);assert struct.unpack_from('<I',obj,0x14)[0]==port and struct.unpack_from('<Q',source,0x68)[0]==1 and struct.unpack_from('<Q',source,0xa0)[0]==GETPORT and struct.unpack_from('<Q',mode,0x80)[0]==DICT and struct.unpack_from('<I',mode,0x88)[0]==PSET;counts['exact_initial_source_mode_port_and_empty_collection_oracles_checked']+=1
  if c['mode']=='invalid_source':
   assert not dic and not member and not bags and st==first['model_state'];assert any(f['pc']==hex(GETPORT)for f in F)and len(types)==1;counts['invalid_source_preflight_and_no_publication_oracles_checked']+=1
  elif c['zero_port']:
   assert not dic and not member and len(bags)==1 and st['dictionary']=={}and st['members']==[]and st['collections'][hex(SET1)]==[hex(SRC)]and st['bag_counts']=={hex(RL):1};counts['zero_port_collection_without_mapping_or_member_oracles_checked']+=1
  else:
   assert len(dic)==len(member)==len(bags)==1 and dic[0]['before']['registers31'][:3]==[hex(DICT),hex(port),hex(SRC)]and dic[0]['before_source_visit_index']<member[0]['before_source_visit_index']<bags[0]['before_source_visit_index'];assert st['dictionary']=={hex(port):hex(SRC)}and st['collections']=={hex(SET0):[],hex(SET1):[hex(SRC)],hex(BAG):[hex(RL)]}and st['bag_counts']=={hex(RL):1};counts['original_dictionary_then_member_then_bag_order_oracles_checked']+=1
   returned=next(f for f in F if f['pc']=='0x18472dc1c');assert returned['registers31'][0]==hex(c['insert_status'])and st['members']==([]if c['insert_status']else[[hex(PSET),hex(port)]])
   if c['mode']=='insert_error':assert r['boundary']['kind']=='source_registration_returned'and not r['kernel_transfers'];counts['nonzero_member_return_with_persistent_CF_bookkeeping_oracles_checked']+=1
   elif c['mode']=='duplicate_source':assert len(r['registration_returns'])==2 and len(types)==2;counts['repeat_add_skips_second_mapping_membership_and_bag_oracles_checked']+=1
  if c['mode']=='schedule_then_run':
   assert len(r['public_handoffs'])==2 and r['public_handoffs'][-1]['kind']=='AddSource_to_runloop'and len(r['kernel_transfers'])==1 and r['kernel_transfers'][0]['registers31'][4]==hex(PSET)
   lookup=next(e for e in model if e['pc']=='0x18489b724');assert lookup['before']['registers31'][:2]==[hex(DICT),hex(port)]and lookup['patches'][0]['after_hex']==struct.pack('<4Q',0,port,SRC,1).hex();assert lookup['model_state_before']['dictionary']=={hex(port):hex(SRC)}and dic[0]['before_source_visit_index']<lookup['before_source_visit_index'];assert not any(e['pc']==hex(DGET)for e in r['imports']);counts['original_wrappers_consume_registration_produced_mapping_oracles_checked']+=1
   cf={int(f['pc'],16):f for f in r['CF_frames']};start=cf[DO_SOURCE]['source_visit_index'];seq=old['cases'][j]['source_visits'];assert r['source_visits'][start:start+len(seq)]==seq;assert cf[0x100425f78]['registers31'][:4]==[hex(OBJ),hex(USER),'0x50','0x0'];counts['unchanged_original_daemon_application_suffixes_checked']+=1
   expected=bytearray(bytes.fromhex(k['final_user8192_hex'])[:148]);struct.pack_into('<I',expected,0,0x80001112);assert r['final_user8192_hex'][:296]==expected.hex()and r['final_OOL16384_hex']==k['final_OOL16384_hex'];counts['complete_received_wire_and_OOL_oracles_checked']+=1
   if j>=2:assert r['boundary']['kind']=='original_runloop_returned'and r['boundary']['registers31'][0]=='0x4'
   else:assert r['boundary']['kind']=='before_pthread_self'
  else:assert r['boundary']['kind']=='source_registration_returned'and not r['runloop_frames']and not r['kernel_transfers']
  rows.append({'case':case_index,'mode':c['mode'],'kernel_case':j,'source_port':hex(port),'mode_portset':hex(PSET),'original_instruction_visits':len(r['source_visits']),'mapping_published':bool(st['dictionary']),'modeled_member_inserted':bool(st['members']),'boundary':r['boundary']['kind']});print(json.dumps(rows[-1]),flush=True)
 assert counts['captured_cache_instructions']==2309 and counts['complete_AddSource_body_instructions']==261 and rt['original_instruction_visits_checked']==12113 and kt['source_visits_checked']==10652 and rt['whole_final_private_RAM_bytes_checked']==34603008
 rejected=[];control=p['cases'][0]
 for tag in('original_instruction_word','member_trap_return','lookup_bucket_value','final_dictionary'):
  bad=copy.deepcopy(control)
  if tag=='original_instruction_word':bad['source_visits'][11]['bytes_hex']='00000000'
  elif tag=='final_dictionary':bad['final_model_state']['dictionary']={'0x403':'0x0'}
  else:
   pc=hex(INSERT_TRAP)if tag=='member_trap_return'else'0x18489b724'
   for key in('imports','runloop_models','scheduling_models'):
    for e in bad[key]:
     if e['pc']==pc:
      if tag=='member_trap_return':e['result']='0x4'
      else:e['patches'][0]['after_hex']=struct.pack('<4Q',0,0x403,0,0).hex()
  try:Replay(bad,p['kernel_cases'][2],s).run()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('accepted altered evidence',tag))
 counts['altered_evidence_controls_rejected']=len(rejected);out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','cf_runloop_handoff_profiles.json','cf_daemon_request_profiles.json','replay_kernel_request_delivery.py']},'source_recapture_match':True,'SDK_declaration_context':sdk_evidence,'verified_counts':dict(counts),'independent_A64_replay':dict(rt),'fresh_kernel_delivery_replay':dict(kt),'altered_evidence_rejected':rejected,'case_summaries':rows,'all_checks_pass':True,**FLAGS};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(counts),'independent_A64_replay':dict(rt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
