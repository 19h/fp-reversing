#!/usr/bin/env python3
"""Fresh original carrier cases and independent byte/epoch/source validation.

O(C*(B+V+E)+I+256R) time and O(retained case/source records) space plus SMT.
No provider, crypto, native API, Mach, credentials or IDB operation executes.
"""
import collections,hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,selected
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from probe_carrier_control import Carrier,cases
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'carrier_control_contracts.json').read_text());p=json.loads((ROOT/'carrier_control_profiles.json').read_text());proof=json.loads((ROOT/'carrier_control_proofs.json').read_text());counts=collections.Counter();deps=set()
 for obj,name in[(c,'recover_carrier_control.py'),(p,'probe_carrier_control.py'),(proof,'prove_carrier_control.py')]:
  assert obj['generator_sha256']==sha(ROOT/name);deps.add(name)
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n;deps.add(n)
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for f in c['functions']:
  assert function(k,e,int(f['start'],16))==f;assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex'];counts['original_functions']+=1
 for r in c['spans']:
  a,z=int(r['start'],16),int(r['end'],16);raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a)and raw.hex()==r['bytes_hex']and hashlib.sha256(raw).hexdigest()==r['sha256'];assert [{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]==r['instructions'];counts['original_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for r in c['bank_rules']:
  b=selected(int(r['left'],16),int(r['right'],16),int(r['key'],16),int(r['additive'],16))
  assert all(r[n]==v for n,v in b.items());assert IMAGE.read(int(r['left'],16),256).hex()==r['left256_hex']and IMAGE.read(int(r['right'],16),256).hex()==r['right256_hex'];assert pointer(k,int(r['slot'],16))==r['original_pointer'];counts['exhaustive_banks']+=1;counts['bank_byte_inputs']+=256
 for r in c['pool_bindings']:assert pointer(k,int(r['original_pointer']['slot'],16))==r['original_pointer'];assert int(r['effective_pointer'],16)==int(r['original_pointer']['target'],16)+r['bias'];counts['pool_bindings']+=1
 for r in c['parent_contexts']:
  f=function(k,e,int(r['start'],16));assert f['sha256']==r['sha256']and f['end']==r['end']and len(f['instructions'])==r['instructions'];assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex'];writers=[i for i in f['instructions']if i['mnemonic']in['add','sub','mov','ldp']and i['operands'].startswith(('sp,','x29,'))];assert writers==r['literal_SP_FP_writers'];counts['parent_instructions']+=len(f['instructions']);counts['literal_SP_pivots']+=sum(i['mnemonic']=='mov'and i['operands'].startswith('sp,')for i in writers)
 for r in c['associated_C']:
  path=Path(r['path']);assert sha(path)==r['sha256'];assert ''.join(path.read_text().splitlines(keepends=True)[r['first_line']-1:r['last_line']])==r['text'];counts['associated_C_excerpts']+=1
 for q in proof['proofs']:
  assert sha(ROOT/q['file'])==q['sha256'];s=z3.Solver();s.from_string((ROOT/q['file']).read_text());assert str(s.check())==q['result']=='unsat';counts['proofs_unsat']+=1
 assert proof['contracts_sha256']==sha(ROOT/'carrier_control_contracts.json');assert [r['input']for r in p['cases']]==list(cases());fresh=[]
 zero={i for a,z in[(0,34),(36,89),(96,104)]for i in range(a,z)};assert len(zero)==95;holes=set(range(104))-zero;assert holes=={34,35,*range(89,96)}
 for old in p['cases']:
  r=Carrier(old['input']).run();assert r==old;fresh.append(r);mode=r['input']['mode'];before=bytearray.fromhex(r['initial_carrier_hex']);expected=before.copy();h=int(r['H'],16);writes={};counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);counts['cases_'+mode]+=1
  for w in r['source_writes']:
   a=int(w['address'],16);data=bytes.fromhex(w['after_hex']);assert len(data)==w['size_bytes']
   for j,b in enumerate(data):
    if h<=a+j<h+104:writes[a+j-h]=b
  if mode in['reset','wrapper_reset_prefix']:
   for i in zero:expected[i]=0
   assert set(writes)==zero;assert len(r['pure_fill_calls'])==3
   for actual,want in zip(r['pure_fill_calls'],c['reset_contract']['fill_calls']):assert actual['pc']==want['pc']and actual['arguments3']==[hex(h+want['destination_offset']),'0x0',hex(want['count_bytes'])]
   counts['reset_written_bytes']+=len(writes);counts['preserved_gap_bytes']+=len(holes)
  elif mode in['heap_controls_11','stack_controls_01']:
   expected[0:2]=bytes([int(mode=='heap_controls_11'),1]);expected[0x24:0x30]=bytes.fromhex('000000000010000000000000');expected[0x38]=0;assert set(writes)=={0,1,*range(0x24,0x30),0x38};counts['producer_control_written_bytes']+=len(writes)
  elif mode=='preparer_operation_zero':expected[0]=0;expected[0x2c:0x30]=bytes.fromhex('78563412');assert set(writes)=={0,*range(0x2c,0x30)}
  elif mode=='preparer_kind_zero':expected[1]=0;assert set(writes)=={1}
  elif mode=='preparer_kind_three':expected[1]=3;assert set(writes)=={1}
  elif mode=='preparer_entry':
   assert not writes;regs=[int(v,16)for v in r['boundary']['registers31']];assert regs[0]==0x600000d100 and regs[1]==0x600000f000 and regs[21]==0x600000a000 and regs[26]==r['input']['selector'];counts['decoded_selector_cases']+=1
  else:raise AssertionError(mode)
  assert bytes(expected).hex()==r['final_carrier_hex'];assert all(expected[i]==v for i,v in writes.items());assert not r['undefined_private_reads']and not r['native_API_executed']and not r['crypto_operation_executed'];counts['carrier_bytes_checked']+=104
 (ROOT/'carrier_control_replays.json').write_text(json.dumps({'scope':'Distinct fresh source cases; opaque synthetic data; no native/provider/crypto execution.','generator_sha256':sha(Path(__file__)),'cases':fresh,'native_target_executed':False},indent=2)+'\n')
 deps.update(['carrier_control_contracts.json','carrier_control_profiles.json','carrier_control_proofs.json']);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'carrier_control_replays.json'),'all_checks_pass':True,'native_target_executed':False,'all_reaching_operation_bytes_boolean_proved':False,'full_goal_complete':False};(ROOT/'carrier_control_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
