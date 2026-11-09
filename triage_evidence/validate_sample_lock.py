#!/usr/bin/env python3
"""Fresh source-only lock/caller/gate checks, exact bindings and SDK compile.

O(C*(B+V+E)+I+256R) time and retained source/event space plus solver work.
No lock/synchronization, native target, provider, crypto or IDB operation runs.
"""
import collections,hashlib,json,re,struct,subprocess
from pathlib import Path
import z3
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,selected
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from probe_kext_close import STACK
from probe_sample_lock import Lock,Gate,lock_cases,gate_cases
from probe_sample_lock_return import Return
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def record_epoch(r,p,n):
 out={}
 for w in r['source_writes']:
  a=int(w['address'],16);b=bytes.fromhex(w['after_hex']);assert len(b)==w['size_bytes']
  for j,v in enumerate(b):
   if p<=a+j<p+n:out[a+j-p]=v
 return out
def main():
 c=json.loads((ROOT/'sample_lock_contracts.json').read_text());p=json.loads((ROOT/'sample_lock_profiles.json').read_text());rp=json.loads((ROOT/'sample_lock_return_profiles.json').read_text());proof=json.loads((ROOT/'sample_lock_proofs.json').read_text());counts=collections.Counter();deps=set()
 for obj,name in[(c,'recover_sample_lock.py'),(p,'probe_sample_lock.py'),(rp,'probe_sample_lock_return.py'),(proof,'prove_sample_lock.py')]:
  assert obj['generator_sha256']==sha(ROOT/name);deps.add(name)
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n;deps.add(n)
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for f in c['functions']:
  assert function(k,e,int(f['start'],16))==f;assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex'];counts['original_functions']+=1
 for f in c['spans']:
  a,z=int(f['start'],16),int(f['end'],16);raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a)and raw.hex()==f['bytes_hex']and hashlib.sha256(raw).hexdigest()==f['sha256'];assert [{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]==f['instructions'];counts['original_spans']+=1
 for b in c['bank_rules']:
  row=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(b[n]==v for n,v in row.items());assert IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex'];assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_banks']+=1;counts['bank_byte_inputs']+=256
 for b in c['primitive_bindings']:
  w=b['wrapper_source'];s=b['stub_source'];wa,sa=int(w['start'],16),int(s['start'],16);assert k.read(wa,8)==IMAGE.read(wa,8)==bytes.fromhex(w['bytes_hex']);assert k.read(sa,16)==IMAGE.read(sa,16)==bytes.fromhex(s['bytes_hex']);wi=list(CS.disasm(k.read(wa,8),wa));si=list(CS.disasm(k.read(sa,16),sa));assert wi[0].mnemonic=='bti'and wi[1].mnemonic=='b'and int(wi[1].op_str[1:],16)==sa;assert [i.mnemonic for i in si]==['adrp','add','ldr','braa'];slot=int(si[0].op_str.split('#')[1],16)+int(si[1].op_str.split('#')[1],16);assert hex(slot)==b['original_pointer']['slot']and si[2].op_str=='x16, [x17]'and si[3].op_str=='x16, x17';assert pointer(k,slot)==b['original_pointer'];target=int(b['original_pointer']['target'],16);assert k.symbols([target])[hex(target)]==b['exact_symbols'];assert k.function(target)==b['kernel_function'];counts['primitive_bindings']+=1;counts['kernel_functions']+=1
 for b in c['selected_routes']:assert pointer(k,int(b['original_pointer']['slot'],16))==b['original_pointer'];counts['selected_routes']+=1
 for b in c['parent_contexts']:
  f=function(k,e,int(b['start'],16));assert all(f[n]==v for n,v in b.items());assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex'];counts['parent_instructions']+=len(f['instructions'])
 for q in proof['proofs']:
  assert sha(ROOT/q['file'])==q['sha256'];s=z3.Solver();s.from_string((ROOT/q['file']).read_text());assert str(s.check())==q['result']=='unsat';counts['proofs_unsat']+=1
 assert proof['contracts_sha256']==sha(ROOT/'sample_lock_contracts.json');header=Path(c['SDK_header']['path']);assert sha(header)==c['SDK_header']['sha256'];lines=header.read_text().splitlines(keepends=True)
 for x in c['SDK_header']['excerpts']:assert ''.join(lines[x['first_line']-1:x['last_line']])==x['text']
 sdk=header.parents[6];sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk');head=sdk/'System/Library/Frameworks/Kernel.framework/Headers';cmd=['clang++','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-I',str(head),'-DKERNEL','-std=c++17','-O2','-S',str(ROOT/'sample_lock_sdk_probe.cpp'),'-o',str(ROOT/'sample_lock_sdk_probe.s')];done=subprocess.run(cmd,capture_output=True,text=True);assert done.returncode==0,(done.stdout,done.stderr);assembly=(ROOT/'sample_lock_sdk_probe.s').read_text();assert re.search(r'mov\s+w0, #2056',assembly),assembly
 sdk_record={'generator_sha256':sha(Path(__file__)),'source_sha256':sha(ROOT/'sample_lock_sdk_probe.cpp'),'header_path':str(header),'header_sha256':sha(header),'command':cmd,'compile_exit':done.returncode,'stderr':done.stderr,'assembly_sha256':sha(ROOT/'sample_lock_sdk_probe.s'),'pointer_width_bytes':8,'void_single_pointer_signatures_checked':4,'target_code_executed':False,'SDK_matches_kernel_build_proved':False};(ROOT/'sample_lock_sdk_checks.json').write_text(json.dumps(sdk_record,indent=2)+'\n');counts['SDK_void_signatures']+=4
 assert [r['input']for r in p['lock_cases']]==list(lock_cases());assert [r['gate_input']for r in p['gate_cases']]==list(gate_cases());locks=[];gates=[];returns=[]
 for old in p['lock_cases']:
  r=Lock(old['input']).run();assert r==old;locks.append(r);q=r['input'];boundary=r['boundary'];ptr=int(r['record_pointer'],16);explicit=int(r['explicit_lock_fixture'],16);cached=int(r['cached_lock_fixture'],16);counts['fresh_lock_cases']+=1;counts['lock_source_visits']+=len(r['source_visits'])
  if explicit or cached:
   expected=({'acquire':'0xfffffe000a508dd4','release':'0xfffffe000a508de4'}if explicit else{'acquire':'0xfffffe000a508d94','release':'0xfffffe000a508d9c'})[q['phase']];assert boundary['kind']=='before_lock_primitive_wrapper'and boundary['target_wrapper']==expected and int(boundary['X0_argument'],16)==(explicit or cached)and not boundary['target_executed'];assert IMAGE.read(int(boundary['pc'],16),4).hex()==boundary['call_instruction_hex'];counts['primitive_boundaries']+=1;counts['explicit_mutex_boundaries'if explicit else'cached_RW_boundaries']+=1
  else:assert boundary['kind']=='return_without_primitive';counts['returns_without_primitive']+=1
  selector=0x729 if q['phase']=='acquire'else 0xc33;key=((ptr^0x6133a0c8)*0x84d77373)&0xffffffff if q['phase']=='acquire'else((ptr^0x734a22b2)*0x8c229611)&0xffffffff;word=(selector-key)&0xffffffff if q['phase']=='acquire'else selector^key;expect=bytearray.fromhex(r['initial_record_hex']);struct.pack_into('<Q',expect,0,explicit);struct.pack_into('<I',expect,8,word);assert expect.hex()==r['final_record_hex'];epoch=record_epoch(r,ptr,128)
  if q['caller']:
   assert set(epoch)==set(range(12))and bytes(epoch[i]for i in range(12))==bytes(expect[:12]);counts['source_built_lock_records']+=1;counts['record_source_written_bytes']+=12
   if q['phase']=='release':reg=26 if q['caller']=='first'else 25;assert int(boundary['registers31'][reg],16)==q['status32'];counts['preserved_status_snapshots']+=1
  else:assert not epoch;counts['standalone_adapter_cases']+=1
  assert not r['native_lock_executed']and not r['native_API_executed']and not r['undefined_private_reads'];counts['lock_record_bytes_checked']+=128
 for old in p['gate_cases']:
  r=Gate(old['gate_input']).run();assert r==old;gates.append(r);q=r['gate_input'];ptr=int(r['record'],16);epoch=record_epoch(r,ptr+0x24,4);source_reads=[x for x in r['private_reads']if int(x['address'],16)==STACK+0xa000];assert r['initial_carrier_hex']==r['final_carrier_hex']and not r['native_lock_executed'];counts['fresh_gate_cases']+=1;counts['gate_source_visits']+=len(r['source_visits']);counts['unchanged_gate_carrier_bytes']+=104
  if q['kind']=='null':assert not source_reads
  else:assert len(source_reads)==1 and source_reads[0]['size_bytes']==4 and source_reads[0]['pc']=='0xfffffe000a621364'and int.from_bytes(bytes.fromhex(source_reads[0]['bytes_hex']),'little')==q['tag32'];counts['source_header_word_reads']+=1
  recognized=q.get('tag32')in[0x85283019,0x42059342]
  if recognized:assert r['gate_outcome']=='recognized_'+format(q['tag32'],'08x')and not epoch;counts['recognized_header_prefixes']+=1
  else:assert r['gate_outcome']=='return'and epoch=={i:v for i,v in enumerate(bytes.fromhex('bf5b51ce'))};counts['error_gate_returns']+=1
 wanted=[(i,caller)for i,r in enumerate(p['gate_cases'])if r['gate_outcome']=='return'for caller in['first','second']];assert [(r['source_gate_case_index'],r['input']['caller'])for r in rp['cases']]==wanted
 for old in rp['cases']:
  i=old['source_gate_case_index'];g=p['gate_cases'][i];r=Return(g,old['input']['caller']).run();r['source_gate_case_index']=i;assert r==old;returns.append(r);assert r['initial_record_hex'][:128]==g['final_preparer_record64_hex'];assert r['final_record_hex']==r['initial_record_hex'];assert not record_epoch(r,int(r['record_pointer'],16),128);want='0xfffffe000a651758'if r['input']['caller']=='first'else'0xfffffe000a68f770';assert r['boundary']['kind']=='before_caller_dispatch'and r['boundary']['target']==want;assert not r['native_lock_executed']and not r['native_API_executed'];counts['fresh_error_continuations']+=1;counts['error_continuation_visits']+=len(r['source_visits'])
 routes=[]
 for caller,error,yes in[('first',0x510,0xccc),('second',0x753,0xe43)]:
  for marker,ix in[(False,error),(True,yes)]:routes.append({'caller':caller,'status_equals_31ae0066':marker,'index':hex(ix),'original_pointer':pointer(k,TABLE+ix*8)})
 counts['caller_status_routes']=len(routes);counts['all_fresh_cases']=len(locks)+len(gates)+len(returns);counts['all_source_visits']=sum(len(r['source_visits'])for r in locks+gates+returns)
 (ROOT/'sample_lock_replays.json').write_text(json.dumps({'scope':'Distinct fresh original cases with declared private contexts; no native lock/provider/crypto operation.','generator_sha256':sha(Path(__file__)),'lock_cases':locks,'gate_cases':gates,'error_continuations':returns,'native_target_executed':False},indent=2)+'\n');deps.update(['sample_lock_contracts.json','sample_lock_profiles.json','sample_lock_return_profiles.json','sample_lock_proofs.json','sample_lock_sdk_probe.cpp']);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'caller_preparer_return_routes':routes,'fresh_replays_sha256':sha(ROOT/'sample_lock_replays.json'),'SDK_checks_sha256':sha(ROOT/'sample_lock_sdk_checks.json'),'all_checks_pass':True,'native_target_executed':False,'native_lock_executed':False,'native_serialization_proved':False,'crypto_operation_executed':False,'full_goal_complete':False};(ROOT/'sample_lock_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
