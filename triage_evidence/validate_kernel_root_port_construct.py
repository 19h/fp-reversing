#!/usr/bin/env python3
"""Original root construction/namespace/guard/member/service and CF checks.
Fresh CPU replays, original byte recapture and exact semantic oracles; native
allocation, task epochs, control messages and hardware PAC remain unknown.
"""
import copy,json,struct,subprocess
from collections import Counter
from pathlib import Path
from daemon_receive_tools import ROOT
from recover_kernel_root_port_construct import P as PREFIX,FLAGS,sha,build,SDK,CONSTRUCT,GUARD
from replay_kernel_root_port_construct import Replay,CFReplay,RPORT,ROUT,OPTIONS,CONTEXT,PS,NODE,NODE2,TABLE
from replay_kernel_request_delivery import Replay as LoanReplay
from replay_kernel_zone_startup import Replay as ZoneReplay
from replay_rpc502_vm_handoff import decode,P,SIZE
from kernel_vm_mig_tools import Image
from bootpolicy_cache_reader import Cache

def get(n):return json.loads((ROOT/n).read_text())
def q(b,o):return struct.unpack_from('<Q',b,o)[0]
def w(b,o):return struct.unpack_from('<I',b,o)[0]
def h(b,o):return struct.unpack_from('<H',b,o)[0]
def main():
 s=get(PREFIX+'_source.json');p=get(PREFIX+'_profiles.json');prior=get('kernel_portset_delivery_profiles.json');modes=get('cf_mode_construction_profiles.json');loans=get('kernel_request_delivery_profiles.json')['loans'];zones=get('kernel_zone_startup_profiles.json')['cases'];assert s==build();c=Counter();kt=Counter();ct=Counter();lt=Counter();zt=Counter();summaries=[];im=Image()
 for obj,script in((s,'recover_'+PREFIX+'.py'),(p,'probe_'+PREFIX+'.py')):
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj['dependencies'].items():assert sha(ROOT/n)==digest
 assert len(s['functions'])==168 and sum(len(f['instructions'])for f in s['functions'])==22141 and len(p['kernel_cases'])==6 and len(p['CF_cases'])==4 and s['root_construct_trap_binding']['pointer']['target']==hex(CONSTRUCT)and s['root_construct_trap_binding']['signed_selector']==-24
 cache=Cache();cs=s['CF_source']
 for f in cs['CF_functions']+cs['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in cs['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 c.update(complete_kernel_functions_recaptured=168,captured_kernel_instructions=22141,complete_CF_functions_recaptured=43,captured_CF_instructions=3498,cache_files_hashed=9,original_construct_trap24_binding_checked=1,complete_original_caller_options24_checked=1)
 assert s['root_caller_options']['bytes24_hex']=='31'+'00'*23 and {e['pc']for e in s['root_caller_options']['original_producer_writes']}=={'0x18552221c','0x18552222c'}and s['root_caller_options']['context']==hex(CONTEXT)
 for j in(1,2):zt.update(ZoneReplay(im,zones[j]).run())
 assert h(bytes.fromhex(zones[1]['final_zone192_hex']),0x34)==144 and zones[1]['identifier']==22 and zones[2]['identifier']==23
 for r in loans:lt.update(LoanReplay(im,r).run())
 for j,r in enumerate(p['kernel_cases']):
  kt.update(Replay(im,r).run());root=bytes.fromhex(r['final_root144_hex']);entry=bytes.fromhex(r['final_entry6_24_hex']);b=decode(r['final_private_RAM']);cfg=r['configuration'];assert r['raw_root_guard_hex']=='a5'and r['raw_pset_guard_hex']=='a5'and r['raw_link_guard_hex']=='a5'and r['raw_unused_link_guard_hex']=='a5'
  copyin=next(e for e in r['root_models']if e['name']=='declared_exact_options24_user_copyin');assert copyin['before']['registers31'][0]==hex(OPTIONS)and copyin['before']['registers31'][2]=='0x18'
  if cfg.get('copyin_error'):
   assert r['boundary']['kind']=='original_root_construct_error_returned'and r['boundary']['registers31'][0]=='0xa'and root==bytes(144)and r['final_root_name4_hex']=='a5'*4 and q(entry,0)==0 and w(entry,12)==2 and len(r['root_returns'])==1 and len(r['root_models'])==1 and not copyin['patches']and copyin['result']=='0x1';c['options_copyin_failure_before_port_allocation_oracles_checked']+=1
  else:
   assert r['boundary']['kind']=='receive_frontend_returned'and r['boundary']['registers31'][0]=='0x0'and r['final_root_name4_hex']=='07060000'and q(entry,0)==RPORT and w(entry,8)==0x04030001
   assert w(root,0)==0x101 and w(root,4)==1 and q(root,0x78)==CONTEXT and w(root,0x34)==0x607 and q(root,0x28)==0 and h(root,0x38)==0 and h(root,0x3a)==5 and w(root,0x84)==w(root,0x88)==1
   assert w(root,0x10)&0xc00==(0x400 if cfg.get('root_flags')==0x11 else 0xc00)and len(r['root_returns'])==2 and all(e['registers31'][0]=='0x0'for e in r['root_returns'])and len(r['root_models'])==2 and copyin['patches'][0]['after_hex']==struct.pack('<I',cfg.get('root_flags',0x31)).hex()+'00'*20
   first=r['root_returns'][0];created=bytes.fromhex(first['root144_hex']);assert q(created,0x20)==0 and q(created,0x78)==CONTEXT;c['original_receive_send_right_namespace_context_and_guard_oracles_checked']+=1
   node=bytes.fromhex(r['final_link48_hex']);service=bytes.fromhex(r['final_unused_link48_hex']);ps=bytes.fromhex(r['final_pset56_hex']);assert q(node,0)==PS+0x10 and q(node,40)==RPORT+0x10 and q(root,0x20)==NODE+8 and q(ps,32)==NODE+24 and q(ps,40)==NODE2+24 and q(service,0)==(PS+0x10)|1 and q(service,40)==int(r['destination'],16)+0x10;c['same_original_namespace_inactive_root_ready_service_topology_oracles_checked']+=1
   old=prior['kernel_cases'][cfg['producer']];assert r['final_user8192_hex']==old['final_user8192_hex']and r['final_OOL16384_hex']==old['final_OOL16384_hex']and w(bytes.fromhex(r['final_user8192_hex']),12)==int(r['receive_name'],16)!=0x607;c['unchanged_complete_service_wire_and_OOL_delivery_oracles_checked']+=1
  summaries.append({'case':j,'configuration':cfg,'original_visits':len(r['source_visits']),'root_name_hex':r['final_root_name4_hex'],'boundary':r['boundary']['kind']});print(json.dumps(summaries[-1]),flush=True)
 strict=bytearray.fromhex(p['kernel_cases'][2]['final_root144_hex']);non=bytes.fromhex(p['kernel_cases'][4]['final_root144_hex']);struct.pack_into('<I',strict,0x10,w(strict,0x10)&~0x800);assert bytes(strict)==non;c['valid_strict_flag_variation_isolated_to_original_port_bit_oracle_checked']=1
 cs={**cs,'root_caller_options':s['root_caller_options']}
 for j,r in enumerate(p['CF_cases']):
  k=p['kernel_cases'][j];ct.update(CFReplay(r,k,cs).run());construct=next(e for e in r['mode_models']if e['name']=='original_kernel_root_construct_return');member=next(e for e in r['mode_models']if e['name']=='original_kernel_root_member_return');assert construct['original_options24_hex']==s['root_caller_options']['bytes24_hex']and construct['root_kernel_oracle']['name']=='0x607'and member['root_kernel_oracle']['arguments24_hex']==k['root_handoffs'][1]['patches'][0]['after_hex'];old=modes['cases'][j];assert r['source_visits']==old['source_visits']and r['final_user8192_hex']==old['final_user8192_hex']and r['final_OOL16384_hex']==old['final_OOL16384_hex']and r['final_mode512_hex']==old['final_mode512_hex']and r['final_queue128_hex']==old['final_queue128_hex']and r['final_model_state']==old['final_model_state']and r['boundary']['kind']==old['boundary']['kind']
  if j<2:assert r['final_argument_record120_hex']==old['final_argument_record120_hex']
  else:assert r['boundary']['registers31'][0]=='0x4'
  c['original_root_construct_member_service_and_CF_daemon_compositions_checked']+=1
 assert kt['source_visits_checked']==24705 and kt['whole_final_RAM_bytes_checked']==6291456 and ct['original_instruction_visits_checked']==12356 and ct['whole_final_private_RAM_bytes_checked']==12582912 and lt['source_visits_checked']==216
 rejected=[]
 for tag in('root_context_field','root_namespace_rights','root_inactive_link','CF_complete_options','CF_root_name_patch'):
  if tag.startswith('CF_'):
   bad=copy.deepcopy(p['CF_cases'][0])
   for key in('imports','runloop_models','mode_models'):
    e=next(e for e in bad[key]if e['name']=='original_kernel_root_construct_return')
    if tag=='CF_complete_options':e['original_options24_hex']='31'+'00'*15+'ff'*8
    else:e['patches'][0]['after_hex']='03060000'
   replay=lambda:CFReplay(bad,p['kernel_cases'][0],cs).run()
  else:
   bad=copy.deepcopy(p['kernel_cases'][0]);key={'root_context_field':'final_root144_hex','root_namespace_rights':'final_entry6_24_hex','root_inactive_link':'final_link48_hex'}[tag];raw=bytearray.fromhex(bad[key]);raw[0x78 if tag=='root_context_field'else 8 if tag=='root_namespace_rights'else 0]^=1;bad[key]=raw.hex();replay=lambda:Replay(im,bad).run()
  try:replay()
  except AssertionError:rejected.append(tag)
  else:raise AssertionError(('accepted altered record',tag))
 c['altered_evidence_controls_rejected']=len(rejected)
 sdk_code='#include <stddef.h>\n#include <mach/port.h>\n_Static_assert(sizeof(mach_port_options_t)==24,"size");\n_Static_assert(offsetof(mach_port_options_t,flags)==0,"flags");\n_Static_assert(offsetof(mach_port_options_t,mpl)==4,"limit");\n_Static_assert(offsetof(mach_port_options_t,reserved)==8,"union");\n_Static_assert(MPO_CONTEXT_AS_GUARD==1 && MPO_INSERT_SEND_RIGHT==16 && MPO_STRICT==32,"bits");\n';cmd=['/usr/bin/clang','-target','arm64-apple-macosx27.0','-isysroot',str(SDK.parents[3]),'-x','c','-fsyntax-only','-'];run=subprocess.run(cmd,input=sdk_code,text=True,capture_output=True);assert run.returncode==0,(cmd,run.stderr);c['compiled_arm64_SDK_layout_and_flag_assertions_checked']=1
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json',PREFIX+'_profiles.json','recover_'+PREFIX+'.py','probe_'+PREFIX+'.py','replay_'+PREFIX+'.py','kernel_zone_startup_profiles.json','kernel_request_delivery_profiles.json','kernel_portset_delivery_profiles.json','cf_mode_construction_profiles.json','replay_kernel_zone_startup.py','replay_kernel_request_delivery.py']},'source_recapture_match':True,'verified_counts':dict(c),'independent_A64_replay':dict(kt),'independent_CF_replay':dict(ct),'fresh_receiver_loan_replay':dict(lt),'fresh_zone_replay':dict(zt),'SDK_layout_compile':{'command':cmd,'source':sdk_code,'returncode':run.returncode,'stderr':run.stderr,'header_sha256':sha(SDK),'version_equivalence_to_kernel':'unknown'},'altered_evidence_rejected':rejected,'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(c),'kernel':dict(kt),'CF':dict(ct),'loans':dict(lt),'zones':dict(zt),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
