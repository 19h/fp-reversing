#!/usr/bin/env python3
"""Independent reply/startup CPU replay, byte/order oracle and recurrence proof.
O(image bytes+visits+state bytes), O(image bytes+largest case); bounded SMT.
"""
import json,struct,subprocess
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_constructor_request import sha
from replay_kext_constructor_reply_state import Replay
P='kext_constructor_reply_state';RAM=0x6500000000;MT=0xfffffe000cccb088
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());counts=Counter();totals=Counter()
 for obj,name in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 for r in src['ranges']:assert im.k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']
 for v in src['views']:assert im.k.read(int(v['address'],16),64).hex()==v['bytes64_hex']and im.pointer(int(v['name_pointer']['slot'],16))==v['name_pointer']and im.k.read(int(v['name_pointer']['target'],16),len(v['name'])+1)==v['name'].encode()+b'\0'
 for b in src['banks']:
  l=bytes.fromhex(b['left256_hex']);r=bytes.fromhex(b['right256_hex']);assert{n^r[l[n]^int(b['key'],16)]for n in range(256)}=={int(b['constant'],16)}and im.pointer(int(b['slot'],16))==b['original_pointer']
 for p in src['global_pool_pointers']:assert im.pointer(int(p['slot'],16))==p
 for proof in src['proofs']:
  assert sha(ROOT/proof['path'])==proof['sha256'];q=subprocess.run(['z3',str(ROOT/proof['path'])],capture_output=True,text=True,check=True);assert q.stdout.strip()=='unsat'and not q.stderr
 assert len(prof['cases'])==4;state=[0]
 for j in range(1,624):state.append((1812433253*(state[-1]^(state[-1]>>30))+j)&0xffffffff)
 expected_mt=struct.pack('<624I',*state)
 for j,row in enumerate(prof['cases']):
  c=row['configuration'];models=row['API_models'];calls=row['calls'];assert row['output_handle_final_hex']=='a5'*8 and row['final_head_hex']=='00'*8 and all(not int(v,16)for v in row['final_missing_globals_hex'].values());counts['unpublished_head_and_output_cases']+=1
  if c['warm']:
   counts['warm_cases']+=1;assert row['boundary']['kind']=='before_unavailable_address_table_load'and row['boundary']['pc']=='0xfffffe000a5b5180'and row['boundary']['registers31'][13]=='0x0'
   mid=502 if c['mode']==1 else 700;assert struct.unpack_from('<I',bytes.fromhex(row['transport_request88_hex']),28)[0]==mid
   b=bytearray(392);struct.pack_into('<IIQQII',b,0,0x80000000,392,0,0,0,mid+100);struct.pack_into('<I',b,32,2);struct.pack_into('<QII',b,36,RAM+0x87000,0x01000101,4096);struct.pack_into('<QII',b,52,0,0x01000101,0);b[68:76]=bytes.fromhex('0000000001000000');struct.pack_into('<I',b,76,0xbeefed02);struct.pack_into('<II',b,384,4096,0);assert row['declared_reply392_hex']==bytes(b).hex()
   expected_child=bytearray(152);struct.pack_into('<I',expected_child,0,0xbeefed02);struct.pack_into('<Q',expected_child,0x48,RAM+0x88000);struct.pack_into('<I',expected_child,0x50,4096);assert row['final_child152_hex']==bytes(expected_child).hex()
   owner=bytearray(1088);struct.pack_into('<I',owner,4,0x31ae0066);owner[0x31d:0x331]=bytes([0xcd])*20;assert row['final_owner1088_hex']==bytes(owner).hex()
   scratch=bytes.fromhex(row['final_scratch160_hex'])
   for off,value in [(0,RAM+0x23000),(0x18,RAM+0x83000),(0x28,RAM+0x86000),(0x48,RAM+0x24000),(0x58,RAM+0x22000),(0x60,RAM+0x22000),(0x80,RAM+0x70000),(0x90,RAM+0x87000),(0x98,RAM+0x21000)]:assert struct.unpack_from('<Q',scratch,off)[0]==value
   assert[(r['kind'],r['size_bytes'])for r in row['allocations']]==[('aligned',16384),('typed',4096),('data',172),('typed',152),('typed',704),('typed',1088),('data',17)]
   assert row['allocations'][4]['view']=='0xfffffe000847baa0'and row['allocations'][5]['view']=='0xfffffe000847c220'
   assert row['final_MT2496_hex']==expected_mt.hex();counts['MT_words_checked']+=624
   seed=[w for w in row['source_writes']if w['pc']=='0xfffffe000a5b4e54'];steps=[w for w in row['source_writes']if w['pc']=='0xfffffe000a5b4eec'];assert len(seed)==1 and seed[0]['address']==hex(MT)and seed[0]['after_hex']=='00000000'and len(steps)==623
   for index,w in enumerate(steps,1):assert w['address']==hex(MT+index*4)and w['size_bytes']==4 and w['after_hex']==struct.pack('<I',state[index]).hex()
   counts['seed_iteration_stores_checked']+=623
   snapshots={s['pc']:s for s in row['state_snapshots']};regs=[int(v,16)for v in snapshots['0xfffffe000a5b4eac']['registers31']];assert regs[0]==0 and regs[8]==1 and regs[9]==0x95d9e06c and regs[15]==0x6c078965 and regs[16]==0x95d9e06b;assert int(snapshots['0xfffffe000a5b4f18']['registers31'][8],16)==624
   for api in models:
    sym=api['symbol'];args=[int(v,16)for v in api['arguments8']];effects=api['memory_effects']
    if sym=='transport_reply_model':assert api['return_value']=='0x0'and len(effects)==1 and effects[0]['after_hex']==bytes(b).hex();counts['declared_reply_parser_compositions']+=1
    elif sym=='copyout_model':assert args[0]==RAM+0x84000 and args[2]==RAM+0x87000 and len(effects)==1 and effects[0]['address']==hex(args[1])and effects[0]['after_hex']==struct.pack('<Q',RAM+0x88000).hex()
    elif sym=='wire_model':assert args[:5]==[RAM+0x84000,RAM+0x88000,RAM+0x8c000,3,0]and not effects and int(api['return_value'],16)==c['wire_return'];counts['wire_requests']+=1
    elif sym=='calendar_time_model':assert len(effects)==2 and effects[0]['address']==hex(args[0])and effects[1]['address']==hex(args[1])and effects[0]['after_hex']==struct.pack('<Q',1700000000).hex()and effects[1]['after_hex']==struct.pack('<I',123456).hex()
    elif sym=='IOLog_no_effect_model':assert args[0]==0xfffffe000790caf5 and not effects;counts['original_zero_random_stub_calls']+=1
   seq={int(v['target'],16):v for v in calls};assert seq[0xfffffe000a627d54]['pc']=='0xfffffe000a6114c4'
   allocation_models=[m for m in models if m['symbol']=='allocation_model'];shared=next(m for m in allocation_models if m['arguments8'][0]=='0xfffffe000847baa0');own=next(m for m in allocation_models if m['arguments8'][0]=='0xfffffe000847c220');assert shared['before_source_visit_index']<own['before_source_visit_index']<seed[0]['source_visit_index']<steps[-1]['source_visit_index'];counts['shared_owner_seed_order_cases']+=1
   assert not any(w['address']=='0xfffffe000cccca58'for w in row['source_writes']);counts['RPC'+str(mid)+'_reply_cases']+=1
  else:
   counts['cold_cases']+=1;assert row['boundary']['pc']=='0xfffffe000c4ece88'and row['boundary']['registers31'][:2]==['0xfffffe000790ba3c','0x0']and row['transport_request88_hex']is None and row['declared_reply392_hex']is None
   assert[(r['kind'],r['size_bytes'])for r in row['allocations']]==[('aligned',16384),('typed',4096),('typed',104)]and row['allocations'][2]['view']=='0xfffffe000847b460';assert len(models)==3 and not row['state_snapshots']
  totals.update(Replay(im,row).run());print(json.dumps({'case':j,'independent_replay':'pass','visits':len(row['source_visits'])}),flush=True)
 a,b=prof['cases'][0],prof['cases'][2];assert a['source_visits']==b['source_visits']
 for key in ['final_scratch160_hex','final_owner1088_hex','final_child152_hex','final_shared704_hex','final_MT2496_hex','final_head_hex','output_handle_final_hex']:assert a[key]==b[key],key
 counts['wire_return_path_and_state_pairs']+=1
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','replay_'+P+'.py','replay_kext_constructor_request.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':{'cases':len(prof['cases']),'ranges':len(src['ranges']),'captured_instructions':sum(len(r['instructions'])for r in src['ranges']),'views':len(src['views']),'banks256':len(src['banks']),'proofs_unsat':1,**dict(counts)},'independent_A64_replay':dict(totals),'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_application_executed':False,'native_VM_effects_executed':False,'native_hardware_setup_executed':False,'native_clock_executed':False,'constructor_publication_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
