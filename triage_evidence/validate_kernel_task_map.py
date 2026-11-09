#!/usr/bin/env python3
"""Fresh source scan, independent CPU replay and task/map/lock state oracle.
O(text words+visits) time, O(profiles+one private RAM map) space.
No native map replacement, VM removal, hardware switching, IPC or concurrency.
"""
from collections import Counter
import json
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
from recover_kernel_task_map import recover
from replay_kernel_task_map import Replay
P=0x6500000000;TASK=P+0x3c000;OLD=P+0x48000;OTHER=P+0x4a000;NEW=P+0x50000;CUR=P+0x2c000;REMOTE=P+0x2d000
def main():
 source=json.loads((ROOT/'kernel_task_map_source.json').read_text());assert source==recover();p=json.loads((ROOT/'kernel_task_map_profiles.json').read_text());assert p['generator_sha256']==sha(ROOT/'probe_kernel_task_map.py')
 for n,h in p['dependencies'].items():assert sha(ROOT/n)==h
 image=Image();counts=Counter();totals=Counter()
 for r in p['cases']:
  replay=Replay(image,r);totals.update(replay.run());c=r['configuration'];kind=r['kind'];state={n:int(v,16)for n,v in r['final_state'].items()};counts[kind]+=1
  assert state['task_lock']==state['preemption']==0
  if kind!='replace':
   taskmap=0 if c['task_map_null']else OLD;current=OLD if c['current_alias']else OTHER;assert state['task_map']==taskmap and state['current_map']==current and not r['API_models']
   if kind=='current_task':assert int(r['return_X0'],16)==TASK and all(int(x['address'],16)>=int(r['entry_SP'],16)-16 for x in r['source_writes'])
   elif kind=='task_map':assert int(r['return_X0'],16)==taskmap and not r['source_writes']
   else:
    b=r['boundary'];regs=[int(x,16)for x in b['registers31']];assert b['kind']=='before_message_allocation'and regs[:4]==[384,0,2,0]and regs[21]==P+0x28000 and regs[23]==current;counts['source_map_arguments_checked']+=1
  else:
   old=OLD if c['old_nonnull']else 0;new=NEW if c['new_nonnull']else 0;recipient=CUR if c['recipient']=='current'else REMOTE;cleanup=int(c['task_bit4']==0);switch=int(recipient==CUR);assert int(r['return_X0'],16)==old and state['task_map']==state['recipient_map']==new and state['current_map']==(new if switch else OTHER)
   assert state['new_flags']==((c['new_bit25']<<25)|(0x100 if cleanup else 0))and state['new_associated']==(0 if cleanup else TASK)
   names=[x['symbol']for x in r['API_models']];assert names.count('lower_map_switch_request')==switch and names.count('map_range_remove_request')==cleanup and names.count('map_lock_model')==cleanup
   for e in r['API_models']:
    args=[int(x,16)for x in e['arguments8']]
    if e['symbol']=='lower_map_switch_request':assert args[:2]==[CUR,new]
    elif e['symbol']=='map_range_remove_request':assert args[:5]==[NEW,P+0x70000,P+0x78000,0,0]and args[6]==0
    elif e['symbol']=='map_lock_model':assert args[0]==NEW+0x30
    else:raise AssertionError(e['symbol'])
   writes=[x for x in r['source_writes']if int(x['address'],16)==TASK+8];assert len(writes)==2 and writes[0]['pc']=='0xfffffe000bd7e840'and writes[0]['size_bytes']==8 and writes[0]['after_hex']==(7).to_bytes(8,'little').hex()and writes[1]['pc']=='0xfffffe000bd7e91c'and writes[1]['size_bytes']==4 and writes[1]['after_hex']=='00000000'
   counts['lock_pairs']+=1;counts['current_switch_requests']+=switch;counts['new_map_cleanup_requests']+=cleanup
   for addr,want in [(TASK+0x28,new),(recipient+0x428,new),(CUR+0x428,new if switch else OTHER)]:assert int.from_bytes(replay.u.mem_read(addr,8),'little')==want
 for group in p['accessor_send_groups']:
  a,b,c=[p['cases'][j]for j in group];assert[a['kind'],b['kind'],c['kind']]==['current_task','task_map','send_prefix'];cfg=a['configuration'];taskmap=int(b['return_X0'],16);current=int(c['boundary']['registers31'][23],16);assert(taskmap==current)==cfg['current_alias'];counts['matched_context_groups']+=1;counts['aliased_context_groups']+=int(cfg['current_alias'])
 assert counts=={'current_task':8,'task_map':8,'send_prefix':8,'source_map_arguments_checked':8,'replace':18,'lock_pairs':18,'current_switch_requests':8,'new_map_cleanup_requests':8,'matched_context_groups':8,'aliased_context_groups':2},dict(counts)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_task_map_source.json','kernel_task_map_profiles.json','recover_kernel_task_map.py','replay_kernel_task_map.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py']},'verified_counts':{'cases':len(p['cases']),'functions':len(source['functions']),'captured_instructions':sum(len(f['instructions'])for f in source['functions']),'instruction_words_scanned':source['instruction_words_scanned'],'signing_candidates':len(source['signing_candidates']),'direct_replacement_calls':len(source['direct_replacement_calls']),'exact_instruction_roles':len(source['exact_instruction_roles']),**dict(counts)},'independent_A64_replay':dict(totals),'source_recapture_match':True,'all_checks_pass':True,'native_target_executed':False,'native_VM_effects_executed':False,'native_hardware_map_switch_executed':False,'native_IPC_executed':False,'native_thread_synchronization_established':False,'hardware_PAC_executed':False,'complete_FairPlay_round_trip_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'kernel_task_map_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':out['verified_counts'],'replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
