#!/usr/bin/env python3
"""Independent page/lookup CPU replay, source proof and field/branch oracle.
O(image bytes+visits+proof time), O(image bytes+largest case). No target effects.
"""
import hashlib,json,struct,subprocess
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_page_context import sha
from replay_kext_page_context import Replay
P='kext_page_context';F=0x6500010000;C=0x6500020000;PARAM=0x6500022000;O=0x6500024000;O2=0x6500024400;R=0x6500025000;M=0x6500028000;SRC=0x6500030000;DST=0x6500034000;MASK32=0xffffffff
def main():
 im=Image();k=im.k;src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());counts=Counter();totals=Counter()
 for obj,name in [(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 for r in src['ranges']:assert k.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']
 for b in src['banks']:
  l=bytes.fromhex(b['left_bytes256_hex']);r=bytes.fromhex(b['right_bytes256_hex']);assert{n^r[l[n]^int(b['key'],16)]for n in range(256)}=={int(b['constant'],16)}and im.pointer(int(b['slot'],16))==b['original_pointer']
 for v in src['views']:assert k.read(int(v['address'],16),64).hex()==v['bytes64_hex']and im.pointer(int(v['name_pointer']['slot'],16))==v['name_pointer']
 for p in src['proofs']:
  assert sha(ROOT/p['path'])==p['sha256'];r=subprocess.run(['z3',str(ROOT/p['path'])],capture_output=True,text=True,check=True);assert r.stdout.strip()=='unsat'and not r.stderr
 assert len(prof['cases'])==83
 for row in prof['cases']:
  cfg=row['configuration'];token=cfg['token_u64']&MASK32;snaps={s['label']:s for s in row['snapshots']};assert all(s['label']in ['dispatch','lookup_call','lookup_return','offset_guard','child_read','range_guard','extent_guard','owner_flag_guard','mapped_pointer_read']for s in row['snapshots']);dispatch=snaps['dispatch'];frame=bytes.fromhex(dispatch['F64_hex']);args=bytes.fromhex(dispatch['argument_record32_hex']);key=((F^0x97099bc0)*0xef54ff65)&MASK32
  assert(struct.unpack_from('<I',frame,0x10)[0]^key)==0x94f8574b and(struct.unpack_from('<I',frame,0x18)[0]+key)&MASK32==0x3e784ff5
  assert struct.unpack_from('<Q',frame,0x30)[0]==C and struct.unpack_from('<Q',frame,0x28)[0]==int(dispatch['argument_record_address'],16)and struct.unpack_from('<I',args,0)[0]==token and struct.unpack_from('<QQQ',args,8)==(cfg['offset'],SRC,DST);counts['source_argument_records']+=1
  call=snaps['lookup_call'];ret=snaps['lookup_return'];a=int(call['lookup_record_address'],16);b=bytes.fromhex(call['lookup_record24_hex']);out=bytes.fromhex(ret['lookup_record24_hex']);key=((a^0x280834b2)*0xf87ec353)&MASK32;assert(struct.unpack_from('<I',b,8)[0]-key)&MASK32==0xc18 and(struct.unpack_from('<I',b,16)[0]^key)==(token+0x7a2abb13)&MASK32
  found=cfg['registry']in ['head','tail'];assert out[12]==(0x23 if found else 0x22);counts['lookup_hit'if found else'lookup_miss']+=1
  dest=int.from_bytes(b[:8],'little');writes=[e for e in row['source_writes']if e['pc']=='0xfffffe000a5b0ac0'];node_reads=[e for e in row['source_reads']if e['pc']=='0xfffffe000a5b09b4'];next_reads=[e for e in row['source_reads']if e['pc']=='0xfffffe000a5b0a44']
  if found:assert len(writes)==1 and int(writes[0]['address'],16)==dest and int.from_bytes(bytes.fromhex(writes[0]['after_hex']),'little')==(O2 if cfg['registry']=='tail'else O)
  else:assert not writes
  expected_nodes=0 if cfg['registry']=='null'else 2 if cfg['registry']=='tail'else 1;assert len(node_reads)==expected_nodes;assert len(next_reads)==(1 if cfg['registry']in ['miss','tail']else 0);counts['node_token_reads']+=len(node_reads);counts['next_link_reads']+=len(next_reads)
  for m in row['API_models']:
   edge=next(e for e in row['logical_edges']if e['pc']==m['pc']and e['visit']+1==m['before_source_visit_index']);target=int(edge['target'],16);a8=[int(v,16)for v in m['arguments8']]
   if target==0xfffffe000c4b9a08:assert a8[:2]==[0x4000,0x40]and int(m['return_value'],16)==F
   elif target==0xfffffe000c4ba154:assert(a8[0],int(m['return_value'],16))in [(0xfffffe000847bea0,C),(0xfffffe000847b760,PARAM)]
   elif target==0xfffffe000c4ba368:assert(a8[0],a8[1])in [(0xfffffe000847ba60,C),(0xfffffe000847c320,PARAM)]
   else:assert target==0xfffffe000c4b9a24 and a8[:2]==[F,0x4000]
  bad_offset=bool(cfg['offset']&0xfffff00000000fff);normal=found and not bad_offset and cfg['child_present']and cfg['marker']==0xbeefed02 and cfg['record_word8']!=0xabcd
  if normal:assert('range_guard'in snaps);n=cfg['offset']>>12;in_range=n<cfg['word20']+cfg['word28'];assert('extent_guard'in snaps)==in_range
  else:assert'range_guard'not in snaps
  kind=row['boundary']['kind'];counts[kind]+=1
  if kind=='mapped_metadata_frontier':
   assert normal and(cfg['owner_flags28']&0x80)and cfg['offset']>>12<cfg['word20']+cfg['word28'];regs=[int(v,16)for v in row['boundary']['registers31']];assert regs[16]==M+cfg['word40']+32*(cfg['offset']>>12);counts['mapped_entry_address_checks']+=1
   read=[e for e in row['source_reads']if e['pc']=='0xfffffe000a60e0d8'];assert len(read)==1 and int(read[0]['address'],16)==R+0x48 and int.from_bytes(bytes.fromhex(read[0]['bytes_hex']),'little')==M
  elif kind=='record_ABCD_frontier':assert found and not bad_offset and cfg['child_present']and cfg['marker']==0xbeefed02 and cfg['record_word8']==0xabcd
  else:
   status=int(row['boundary']['registers31'][0],16);expected=0xffff5b36 if not found else 0xffff5bef if normal and cfg['owner_flags28']==0 and cfg['offset']>>12<cfg['word20']+cfg['word28']else 0xffff5bd9;assert status==expected;(counts.update({'status_'+hex(status):1}))
  assert row['destination4096_sha256']==hashlib.sha256(bytes([0xa5])*4096).hexdigest()
  assert not any(M<=int(e['address'],16)<M+0x4000 or SRC<=int(e['address'],16)<SRC+0x4000 for e in row['source_reads']);counts['preserved_source_destination_boundaries']+=1
  totals.update(Replay(im,row).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json',P+'_profiles.json','replay_'+P+'.py','kernel_vm_mig_tools.py']},'source_recapture_match':True,'verified_counts':{'cases':83,'ranges':len(src['ranges']),'captured_instructions':sum(len(r['instructions'])for r in src['ranges']),'views':len(src['views']),'banks256':len(src['banks']),'proofs_unsat':len(src['proofs']),**dict(counts)},'independent_A64_replay':dict(totals),'all_checks_pass':True,'native_target_executed':False,'native_VM_effects_executed':False,'native_crypto_executed':False,'native_registry_initialization_established':False,'continuous_constructor_page_close_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':out['verified_counts'],'independent_A64_replay':out['independent_A64_replay'],'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
