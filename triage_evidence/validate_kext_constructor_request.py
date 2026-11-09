#!/usr/bin/env python3
"""Independent source/proof, allocation/fill, mode/packet and fresh CPU checks.
O(image bytes+visits+extent bytes), O(image bytes+largest case), bounded SMT.
"""
import hashlib,json,struct,subprocess
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_constructor_request import sha
from replay_kext_constructor_request import Replay
P='kext_constructor_request';RAM=0x6500000000;STAGE=RAM+0x70000;NAME=RAM+0x90000;HOST=RAM+0x82000;PORT=RAM+0x83000;IMAP=RAM+0x85000;COPY=RAM+0x86000
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());counts=Counter();totals=Counter()
 for obj,name in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 for r in src['ranges']:assert im.k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']
 for v in src['views']:assert im.k.read(int(v['address'],16),64).hex()==v['bytes64_hex']and im.pointer(int(v['name_pointer']['slot'],16))==v['name_pointer']and im.k.read(int(v['name_pointer']['target'],16),len(v['name'])+1)==v['name'].encode()+b'\0'
 for proof in src['proofs']:
  assert sha(ROOT/proof['path'])==proof['sha256'];r=subprocess.run(['z3',str(ROOT/proof['path'])],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr
 assert len(prof['cases'])==25
 for j,row in enumerate(prof['cases']):
  c=row['configuration'];m=c['length']+1;page=1<<(c['page_shift']&31);alloc=(m+page-1)&-page;name=bytes(0x21+k%90 for k in range(c['length']))+b'\0';normal=c['mode']&0xffffffff==1;mid=502 if normal else 700;slot=17 if normal else 34
  assert row['staging_extent_bytes']==alloc and row['staging_final_hex']==(name+bytes(alloc-m)+b'\xa5').hex()and row['name_final_hex']==name.hex()and row['output_handle_final_hex']=='a5'*8
  assert [(r['kind'],r['size_bytes'])for r in row['allocations']]==[('aligned',16384),('typed',4096),('data',172),('typed',152)]
  assert row['allocations'][1]['view']=='0xfffffe000847bea0'and row['allocations'][3]['view']=='0xfffffe000847bd60'
  calls=row['calls'];by={int(v['target'],16):v for v in calls};host=by[0xfffffe000bcf258c];assert host['args8'][:4]==[hex(HOST),'0xffffffff',hex(slot),hex(RAM+0x20018)]
  expected=[(0xfffffe000a508e04,[IMAP,RAM+0x20080,alloc]),(0xfffffe000c647f10,[STAGE,NAME,m]),(0xfffffe000a687d64,[STAGE+m,0,alloc-m]),(0xfffffe000a508e2c,[IMAP,STAGE,m,0,RAM+0x20028])]
  for target,args in expected:assert by[target]['args8'][:len(args)]==[hex(v)for v in args]
  rpc=calls[-1];assert int(rpc['pc'],16)==(0xfffffe000a60b8a8 if normal else 0xfffffe000a60d3bc)and int(rpc['target'],16)==(0xfffffe000a5a2064 if normal else 0xfffffe000a5a22d4)and rpc['args8']==[hex(v)for v in [PORT,COPY,m,c['cpu_type'],c['cpu_subtype'],c['origin']&0xffffffff,RAM+0x22000,RAM+0x21000]]
  expected_message=struct.pack('<IIQQIIIQII8sIQQQ',0x80001513,0,PORT,0,0,mid,1,COPY,0x01000100,m,bytes.fromhex('0000000001000000'),m,c['cpu_type'],c['cpu_subtype'],c['origin']&0xffffffff)
  assert len(expected_message)==88 and row['message88_hex']==expected_message.hex()and row['boundary']['pc']=='0xfffffe000bcf5e28'and row['boundary']['registers31'][1:3]==['0x58','0x190']
  assert int(row['boundary']['registers31'][30],16)==(0xfffffe000a5a20fc if normal else 0xfffffe000a5a236c)
  snaps={s['pc']:s for s in row['snapshots']};assert int(snaps['0xfffffe000a60ab2c']['registers31'][20],16)==0xc96
  a=[int(v,16)for v in snaps['0xfffffe000a60af44']['registers31']];assert a[26]==0xfffffffe and a[12]==0x3332e642601efea0+m
  a=[int(v,16)for v in snaps['0xfffffe000a60b624']['registers31']];assert a[26]==0x3e784ff5 and a[27]==alloc^0x0160484004008104 and a[25]==m+0x3332e642601efea0
  coverage=set()
  for w in row['source_writes']:
   addr=int(w['address'],16);size=w['size_bytes']
   if STAGE<=addr<STAGE+0x10001:
    assert STAGE+m<=addr and addr+size<=STAGE+alloc and bytes.fromhex(w['after_hex'])==bytes(size);coverage.update(range(addr,addr+size))
  assert coverage==set(range(STAGE+m,STAGE+alloc));counts['zero_fill_bytes_checked']+=len(coverage);counts['filename_bytes_checked']+=m;counts['RPC'+str(mid)+'_prefixes']+=1;counts['host_slot'+str(slot)+'_prefixes']+=1;counts['page_shift'+str(c['page_shift'])+'_cases']+=1;counts['handle_output_canaries_preserved']+=1
  for api in row['API_models']:
   args=[int(v,16)for v in api['arguments8']];effects=api['memory_effects'];sym=api['symbol']
   if sym in ['host_special_port_model','kmem_alloc_model','vm_map_copyin_model']:
    dest=args[3]if sym=='host_special_port_model'else args[1]if sym=='kmem_alloc_model'else args[4];value=PORT if sym=='host_special_port_model'else STAGE if sym=='kmem_alloc_model'else COPY;assert len(effects)==1 and effects[0]['address']==hex(dest)and effects[0]['after_hex']==struct.pack('<Q',value).hex()
   elif sym=='memcpy_model':assert len(effects)==1 and effects[0]['address']==hex(STAGE)and effects[0]['after_hex']==name.hex()and effects[0]['before_hex']=='a5'*m
   else:assert sym in ['aligned_allocation_model','allocation_model','host_priv_self_model','strlen_model']and not effects
  totals.update(Replay(im,row).run());print(json.dumps({'case':j,'RPC':mid,'allocation_bytes':alloc,'independent_replay':'pass'}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','replay_'+P+'.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':{'cases':len(prof['cases']),'ranges':len(src['ranges']),'captured_instructions':sum(len(r['instructions'])for r in src['ranges']),'views':len(src['views']),'proofs_unsat':len(src['proofs']),**dict(counts)},'independent_A64_replay':dict(totals),'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_VM_effects_executed':False,'native_reference_balance_established':False,'constructor_publication_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
