#!/usr/bin/env python3
"""Independent close CPU replay, list/VM/order and overwrite-byte oracle.
O(image bytes+visits), O(image bytes+largest case), bounded proof replay.
"""
import hashlib,json,struct,subprocess
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_context_retirement import sha,byte_ref
from replay_kext_context_retirement import Replay
P='kext_context_retirement';R=0x6500024000;M=0x6500028000;AUX=0x650002c000;KMAP=0x6500030000;CELL=0xfffffe000cccca58;MASK64=(1<<64)-1
def main():
 im=Image();k=im.k;src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());counts=Counter();totals=Counter()
 for obj,name in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 for r in src['ranges']:assert k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']
 for v in src['views']:assert k.read(int(v['address'],16),64).hex()==v['bytes64_hex']and im.pointer(int(v['name_pointer']['slot'],16))==v['name_pointer']and k.read(int(v['name_pointer']['target'],16),len(v['name'])+1)==v['name'].encode()+b'\0'
 for b in src['banks']:
  l=bytes.fromhex(b['left_bytes256_hex']);r=bytes.fromhex(b['right_bytes256_hex']);assert{n^r[l[n]^int(b['key'],16)]for n in range(256)}=={int(b['constant'],16)}and im.pointer(int(b['slot'],16))==b['original_pointer']
 for proof in src['proofs']:
  assert sha(ROOT/proof['path'])==proof['sha256'];q=subprocess.run(['z3',str(ROOT/proof['path'])],capture_output=True,text=True,check=True);assert q.stdout.strip()=='unsat'and not q.stderr
 assert src['byte_table256_hex']==bytes(byte_ref(n)for n in range(256)).hex()and len(prof['cases'])==28
 for row in prof['cases']:
  c=row['configuration'];target=int(row['target_owner'],16);initial={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in row['initial_private_fixtures']};nodes=[int(a,16)for a in row['final_nodes_hex']];expected={a:bytearray(initial[a])for a in nodes};remaining=[a for a in nodes if a!=target];counts['placement_'+c['placement']]+=1
  assert int(row['boundary']['registers31'][0],16)==(0 if target else 0xffff5b36)
  assert int.from_bytes(bytes.fromhex(row['final_head_hex']),'little')==(remaining[0]if remaining else 0)
  for j,a in enumerate(remaining):struct.pack_into('<QQ',expected[a],8,remaining[j-1]if j else 0,remaining[j+1]if j+1<len(remaining)else 0)
  expected_calls=[]
  if target:
   if c['resource']in ['primary','both']:expected_calls.extend([('unwire',0xfffffe000a508e14,[KMAP,M,M+0x4000,0]),('primary_deallocate',0xfffffe000a508e1c,[KMAP,M,4096])])
   if c['resource']in ['secondary','both']:expected_calls.append(('secondary_deallocate',0xfffffe000a508e1c,[KMAP,AUX,512]))
   if c['resource']!='none':expected_calls.append(('child_free',0xfffffe000c4ba368,[0xfffffe000847bc60,R]))
   expected_calls.append(('owner_free',0xfffffe000c4ba368,[0xfffffe000847ba20,target]))
  edges={(e['pc'],e['visit']+1):e for e in row['logical_edges']};close_models=[]
  for m in row['API_models']:
   e=edges[(m['pc'],m['before_source_visit_index'])]
   if e['phase']=='close':close_models.append((m,e))
   else:assert c['page_preface']and int(e['target'],16)in [0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4b9a24]
  assert len(expected_calls)==len(close_models)
  for (name,t,args),(m,e)in zip(expected_calls,close_models):
   assert int(e['target'],16)==t and m['arguments8'][:len(args)]==[hex(v)for v in args]and int(m['return_value'],16)==(c['VM_return']if name in ['unwire','primary_deallocate','secondary_deallocate']else 0);counts[name+'_requests']+=1
  wipes=[e for e in row['source_writes']if e['pc']=='0xfffffe000a5c1520'];links=[e for e in row['source_writes']if e['pc']in ['0xfffffe000a5c12b0','0xfffffe000a5c1350','0xfffffe000a5c13e4']]
  if target:
   counts['successful_closes']+=1;assert len(wipes)==1088;entry=next(e for e in row['snapshots']if e['label']=='overwrite_entry');regs=[int(v,16)for v in entry['registers31']];s=int(entry['SP'],16);seed=(((s+0x68)^0xbffb8c1fde3fdf76)+(((s+0x68)<<1)&0x7ff7183fbc7fbee0)+0x51e6f7fbbfe77eec)&MASK64;assert regs[1]==target and regs[9]==seed and regs[10]==1088 and(regs[11]+regs[21])&MASK64==MASK64
   for j,w in enumerate(wipes):
    off=1087-j;v=byte_ref((seed+j)&255);assert int(w['address'],16)==target+off and w['size_bytes']==1 and w['after_hex']==bytes([v]).hex();expected[target][off]=v
   counts['overwrite_bytes_checked']+=1088
   owner_free=close_models[-1][0];assert wipes[-1]['source_visit_index']<owner_free['before_source_visit_index'];assert links and max(e['source_visit_index']for e in links)<wipes[0]['source_visit_index'];counts['unlink_before_overwrite_before_free']+=1
   child=[m for(m,e)in close_models if m['pc']=='0xfffffe000a5c1170']
   if child:assert child[0]['before_source_visit_index']<min(e['source_visit_index']for e in links);counts['child_free_before_unlink']+=1
  else:assert not wipes and not links and not close_models;counts['lookup_miss_returns']+=1
  for a,b in expected.items():assert row['final_nodes_hex'][hex(a)]==bytes(b).hex()
  assert row['final_record152_hex']==initial[R].hex()and row['destination4096_sha256']==hashlib.sha256(bytes([0xa5])*4096).hexdigest()
  if c['page_preface']:
   assert len(row['declared_call_transitions'])==1;t=row['declared_call_transitions'][0];assert t['page_return_u32']==('0xffff5bef'if c['page_preface']=='owner_flag'else'0xffff5bd9')and t['head_hex']==struct.pack('<Q',nodes[0]).hex()and t['record152_hex']==initial[R].hex()
   for a,b in t['nodes_hex'].items():assert b==initial[int(a,16)].hex()
   counts['page_error_close_compositions']+=1
  else:assert not row['declared_call_transitions']
  totals.update(Replay(im,row).run())
 for a,b in [(2,20),(4,21)]:assert prof['cases'][a]['source_visits']==prof['cases'][b]['source_visits']and prof['cases'][a]['final_nodes_hex']==prof['cases'][b]['final_nodes_hex'];counts['VM_status_pairs']+=1
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','replay_'+P+'.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':{'cases':28,'ranges':len(src['ranges']),'captured_instructions':sum(len(r['instructions'])for r in src['ranges']),'views':len(src['views']),'banks256':len(src['banks']),'proofs_unsat':len(src['proofs']),**dict(counts)},'independent_A64_replay':dict(totals),'all_checks_pass':True,'native_target_executed':False,'native_VM_effects_executed':False,'native_free_executed':False,'native_reference_balance_established':False,'continuous_native_constructor_page_close_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'independent_A64_replay':out['independent_A64_replay'],'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
