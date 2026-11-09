#!/usr/bin/env python3
"""Independent source recapture, CPU replay and cleanup argument oracle.
O(source bytes+visits+cases) time; O(image bytes+largest case) space.
"""
import hashlib,json,struct,subprocess
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from replay_kext_mapped_cleanup import Replay,seed_components
PREFIX='kext_mapped_cleanup';MASK=(1<<64)-1
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 im=Image();k=im.k;src=json.loads((ROOT/f'{PREFIX}_source.json').read_text());prof=json.loads((ROOT/f'{PREFIX}_profiles.json').read_text());counts={};models={};ignored=0
 for obj,name in [(src,'recover_kext_mapped_cleanup.py'),(prof,'probe_kext_mapped_cleanup.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
 for r in src['ranges']:assert k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']and hashlib.sha256(bytes.fromhex(r['bytes_hex'])).hexdigest()==r['sha256']
 for b in src['banks']:
  l=bytes.fromhex(b['left_bytes256_hex']);r=bytes.fromhex(b['right_bytes256_hex']);key=int(b['key'],16);assert{n^r[l[n]^key]for n in range(256)}=={int(b['constant'],16)};assert im.pointer(int(b['slot'],16))==b['original_pointer']
 for root in src['bank_roots']:assert im.pointer(int(root['pointer']['slot'],16))==root['pointer']and int(root['pointer']['target'],16)+root['bias']==int(root['bank_root'],16)
 for ptr in src['import_pointers']:assert im.pointer(int(ptr['slot'],16))==ptr
 # Independently audit retained encoding candidates; the full normalized-
 # segment scan is reproduced by the source generator.
 for row in src['unsigned_STR64_2e8_candidates']:
  w=struct.unpack('<I',k.read(int(row['pc'],16),4))[0];assert w==int(row['word'],16)and w&0xffc00000==0xf9000000 and(w>>10)&0xfff==0x5d and row['base_register']==(w>>5)&31 and row['base_is_SP']==(((w>>5)&31)==31)
 assert len(src['unsigned_STR64_2e8_candidates'])==14 and sum(not x['base_is_SP']for x in src['unsigned_STR64_2e8_candidates'])==7
 for p in src['proofs']:
  assert sha(ROOT/p['path'])==p['sha256'];r=subprocess.run(['z3',str(ROOT/p['path'])],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr
 assert len(prof['cases'])==60
 for row in prof['cases']:
  f=row['fixture'];memory={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in row['initial_memory']};parent=memory[0x6100001000];record=memory[0x6100002000];assert struct.unpack_from('<Q',parent,0x2e8)[0]==(0x6100002000 if f['record_present']else 0)
  assert struct.unpack_from('<Q',record,0x48)[0]==f['address']and struct.unpack_from('<I',record,0x50)[0]==f['extent']and struct.unpack_from('<Q',record,0x58)[0]==f['aux_address']and struct.unpack_from('<I',record,0x60)[0]==f['aux_extent']
  assert memory[0xfffffe0007e6d9c0]==struct.pack('<I',f['page_shift'])and memory[0xfffffe0007f860a8]==struct.pack('<Q',0x6100004000)
  expected=[]
  if f['record_present']:
   if f['address']:
    mask=MASK^((1<<f['page_shift'])-1);expected.extend([('unwire',0xfffffe000a508e14,0xdff5,[0x6100004000,f['address']&mask,((f['address']+f['extent']+(1<<f['page_shift'])-1)&MASK)&mask,0]),('deallocate_primary',0xfffffe000a508e1c,0x8bbb,[0x6100004000,f['address'],f['extent']])])
   if f['aux_address']:expected.append(('deallocate_aux',0xfffffe000a508e1c,0x8bbb,[0x6100004000,f['aux_address'],f['aux_extent']]))
   expected.append(('typed_free_record',0xfffffe000c4ba368,0x4d6a,[0xfffffe000847bc60,0x6100002000]))
  assert len(expected)==len(row['models'])
  for e,m in zip(expected,row['models']):
   name,t,mod,args=e;assert m['name']==name and int(m['target'],16)==t and int(m['modifier'],16)==mod and m['arguments8'][:len(args)]==[hex(x)for x in args];assert int(m['return_status'],16)==f['return_status'];models[name]=models.get(name,0)+1
  assert row['final_record_bytes_hex']==record.hex()and row['final_parent_bytes_hex']==parent.hex()
  r=Replay(k,row).run()
  for key,value in r.items():counts[key]=counts.get(key,0)+value
 for j in range(0,60,2):
  a,b=prof['cases'][j:j+2];assert[a['name']for a in a['models']]==[b['name']for b in b['models']];assert a['source_visits']==b['source_visits'];ignored+=1
 seed=seed_components(k)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kext_mapped_cleanup_source.json','kext_mapped_cleanup_profiles.json','replay_kext_mapped_cleanup.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'independent_A64_replay':counts,'verified_counts':{'cases':60,'ranges':len(src['ranges']),'captured_instructions':sum(len(r['instructions'])for r in src['ranges']),'banks256':len(src['banks']),'proofs_unsat':len(src['proofs']),'return_status_pairs':ignored,**models},'source_seed_components':seed,'all_checks_pass':True,'native_target_executed':False,'native_VM_effects_executed':False,'native_record_publication_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/f'{PREFIX}_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'independent_A64_replay':counts,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
