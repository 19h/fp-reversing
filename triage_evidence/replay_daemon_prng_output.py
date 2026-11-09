#!/usr/bin/env python3
"""Full-prefix independent A64 replay of two PRNG-driven arena updates.
O(cases*(prefix+visits+effects+SSA bytes)) time,O(largest trace) space.
Finite-read addresses are concretized from declared API inputs, then checked
against actual A64 effective addresses. No import/PAC/native target runs.
"""
import hashlib,json
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE
from replay_daemon_seed_material import MaterialReplay,INPUTS,compact,unpack
from replay_daemon_entropy_return import expr,concrete,ARRAY
from daemon_prng_output_symbolic import START

def twist(words):
 a=words.copy()
 for i in range(624):
  y=(a[i]&0x80000000)|(a[(i+1)%624]&0x7fffffff);a[i]=(a[(i+397)%624]^(y>>1)^(0x9908b0df if y&1 else 0))&0xffffffff
 return a

def temper(v):
 v^=v>>11;v^=(v<<7)&0x9d2c5680;v^=(v<<15)&0xefc60000;return(v^(v>>18))&0xffffffff

class OutputReplay(MaterialReplay):
 def __init__(self,c,prefix,entropy,material,output,cfg,pattern):
  self.output=output;self.output_phase=False;self.checkpoints=[];super().__init__(c,prefix,entropy,material,cfg,pattern)
 def code(self,u,a,n,d):
  if self.forward and self.output_phase and a==0x100350628:
   self.finish();raw=bytes(u.mem_read(ARRAY,2496));destination=int.from_bytes(bytes(u.mem_read(0x1010c8278,8)),'little');self.checkpoints.append({'source_visits_completed':self.index,'state_sha256':hashlib.sha256(raw).hexdigest(),'state_words':[int.from_bytes(raw[j:j+4],'little')for j in range(0,2496,4)],'global_index':int.from_bytes(bytes(u.mem_read(0x1010c67dc,4)),'little'),'global_counter':int.from_bytes(bytes(u.mem_read(0x1010c8258,4)),'little'),'destination':hex(destination),'destination_first8_hex':bytes(u.mem_read(destination,8)).hex()})
  return super().code(u,a,n,d)
 def run_output(self):
  prefix_result=super().run_material();prior_counts=Counter(self.counts);prior_len=len(self.trace['steps']);destination=int.from_bytes(bytes(self.u.mem_read(0x1010c8278,8)),'little');old_words=[int.from_bytes(bytes(self.u.mem_read(destination+4*j,4)),'little')for j in range(2)];assert self.H<=destination<destination+8<=self.H+90000
  for node in self.output['definitions'][len(self.material['definitions']):]:assert node['name']not in self.values;self.values[node['name']]=expr(node['expression'],self.values)
  extra=concrete(self.output['steps'],self.values)
  for row in extra:
   for event in row['events']:
    if'address_expression'in event:event['address']=hex(int.from_bytes(bytes.fromhex(event['address_expression']['hex']),'little'));assert event['address']in event['candidate_addresses']
  self.trace={'steps':self.trace['steps']+extra,'boundary':concrete(self.output['boundary'],self.values),'origins':self.output['origins']};self.forward_done=False;self.output_phase=True;self.u.emu_start(START,0,count=len(extra)+10);assert self.forward_done and len(self.checkpoints)==2 and len(self.backing)==112
  state,_=compact(self.cfg,int(prefix_result['cursor_source_pointer'],16));expected=[]
  for j,checkpoint in enumerate(self.checkpoints):
   state=twist(state);assert checkpoint['state_words']==state;word=temper(state[j]);expected.append(word);assert checkpoint['global_index']==checkpoint['global_counter']==j+1
   raw=bytes.fromhex(checkpoint['destination_first8_hex']);actual=[int.from_bytes(raw[k:k+4],'little')for k in [0,4]]
   for k in range(j+1):assert actual[k]==old_words[k]^expected[k]
   checkpoint['selected_state_index']=j;checkpoint['untempered_word']=hex(state[j]);checkpoint['tempered_word']=hex(word);del checkpoint['state_words']
  diff=Counter(self.counts);diff.subtract(prior_counts);assert diff['source_visits']==len(extra)and self.index==prior_len+len(extra)
  return {'input':self.c,'values':self.cfg,'pattern':self.pattern,'prefix_verified_counts':dict(prior_counts),'new_verified_counts':dict(diff),'verified_counts':dict(self.counts),'prefix_certificate':{'state_sha256':prefix_result['mixed_state']['sha256'],'cursor_source_pointer':prefix_result['cursor_source_pointer'],'source_visits':prior_counts['source_visits']},'initial_buffer_words':[hex(x)for x in old_words],'checkpoints':self.checkpoints,'finite_reads_checked':len(self.output['lookups']),'API_models_count':len(self.models),'frontier':self.trace['boundary'],'native_target_executed':False,'native_entropy_or_time_executed':False}

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=json.loads((ROOT/'daemon_prng_output_profiles.json').read_text());prior=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());entropy=json.loads((ROOT/'daemon_entropy_return_profiles.json').read_text());material=json.loads((ROOT/'daemon_seed_material_profiles.json').read_text());base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());rows=[]
 for c in p['cases']:
  index=c['prior_case_index'];args=[base['cases'][index]['input'],unpack(next(x for x in prior['cases']if x['prior_case_index']==index)),unpack(next(x for x in entropy['cases']if x['prior_case_index']==index)),unpack(next(x for x in material['cases']if x['prior_case_index']==index)),unpack(c)]
  for cfg,pattern in [(INPUTS[0],0),(INPUTS[3],3)]:
   r=OutputReplay(*args,cfg,pattern).run_output();r['prior_case_index']=index;rows.append(r);print(json.dumps({'case':index,'values':cfg['name'],'source_visits':r['verified_counts']['source_visits'],'new_source_visits':r['new_verified_counts']['source_visits'],'completed':len(rows)}),flush=True)
 deps=['daemon_prng_output_profiles.json','daemon_prng_output_symbolic.py','daemon_prng_output_runner.py','daemon_seed_material_profiles.json','daemon_context_transfer_profiles.json','daemon_entropy_return_profiles.json','daemon_arena_storage_profiles.json','replay_daemon_seed_material.py','replay_daemon_entropy_return.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_prng_output_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'replays':len(rows),'source_visits':sum(x['verified_counts']['source_visits']for x in rows),'new_source_visits':sum(x['new_verified_counts']['source_visits']for x in rows)}),flush=True)
if __name__=='__main__':main()
