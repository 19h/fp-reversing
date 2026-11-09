#!/usr/bin/env python3
"""Fresh RW source-prefix/ABI checks and independent metadata/census audit.

O(C*(B+V+E)+I+256R) time and retained source/event space plus SMT/compiler.
No native heap, synchronization, group accounting, provider or IDB action.
"""
import collections,hashlib,json,re,struct,subprocess
from pathlib import Path
import z3
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,selected,qword
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function,starts
from recover_kext_cold_init import pointer
from resolve_kernel_collection_interfaces import commands
from probe_rw_lifecycle import Prefix,init_cases,api_cases,legacy_cases,OBJ,ATTR,GROUP,WORDS,CELL,TABLE
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def epoch(r,a,n):
 out={}
 for w in r['source_writes']:
  p=int(w['address'],16);b=bytes.fromhex(w['after_hex']);assert len(b)==w['size_bytes']
  for j,v in enumerate(b):
   if a<=p+j<a+n:out[p+j-a]=v
 return out
def check_visits(k,r,counts):
 for i in r['source_visits']:
  a=int(i['pc'],16);raw=k.read(a,4)if i['source']=='kernel'else IMAGE.read(a,4);assert raw.hex()==i['bytes_hex'];counts['source_byte_checks']+=4
 assert not r['private_undefined_reads']and not r['native_API_executed']and not r['group_accounting_executed']and not r['heap_backend_executed']and not r['entry_reachability_proved']
def main():
 c=json.loads((ROOT/'rw_lifecycle_contracts.json').read_text());p=json.loads((ROOT/'rw_lifecycle_profiles.json').read_text());proof=json.loads((ROOT/'rw_lifecycle_proofs.json').read_text());counts=collections.Counter();deps=set()
 for obj,name in[(c,'recover_rw_lifecycle.py'),(p,'probe_rw_lifecycle.py'),(proof,'prove_rw_lifecycle.py')]:
  assert obj['generator_sha256']==sha(ROOT/name);deps.add(name)
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n;deps.add(n)
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for f in c['functions']:
  assert function(k,e,int(f['start'],16))==f;assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex'];counts['kext_functions']+=1
 for f in c['kernel_functions']:assert k.function(int(f['start'],16))==f;counts['kernel_functions']+=1
 for f in c['spans']:
  a,z=int(f['start'],16),int(f['end'],16);assert k.read(a,z-a)==IMAGE.read(a,z-a)==bytes.fromhex(f['bytes_hex']);assert hashlib.sha256(k.read(a,z-a)).hexdigest()==f['sha256'];counts['original_spans']+=1
 for b in c['bank_rules']:
  v=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(b[n]==x for n,x in v.items());assert IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex'];assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_banks']+=1;counts['bank_byte_inputs']+=256
 for b in c['original_bindings']:
  w,s=b['wrapper'],b['stub'];wa,sa=int(w['start'],16),int(s['start'],16);assert k.read(wa,8)==IMAGE.read(wa,8)==bytes.fromhex(w['bytes_hex']);assert k.read(sa,16)==IMAGE.read(sa,16)==bytes.fromhex(s['bytes_hex']);wi=list(CS.disasm(k.read(wa,8),wa));si=list(CS.disasm(k.read(sa,16),sa));assert wi[1].mnemonic=='b'and int(wi[1].op_str[1:],16)==sa;slot=int(si[0].op_str.split('#')[1],16)+int(si[1].op_str.split('#')[1],16);assert pointer(k,slot)==b['original_pointer'];assert k.symbols([int(b['original_pointer']['target'],16)])[b['original_pointer']['target']]==b['exact_symbols'];counts['native_API_bindings']+=1
 d=c['typed_site'];raw=k.read(int(d['address'],16),64);assert raw.hex()==d['bytes64_hex']and raw[:16]==bytes(16);assert struct.unpack_from('<II',raw,40)==(0x6a,16)
 for name in['site_name_pointer','signature_pointer']:assert pointer(k,int(d[name]['slot'],16))==d[name]
 assert k.read(int(d['site_name_pointer']['target'],16),len(bytes.fromhex(d['site_name_bytes_hex']))).hex()==d['site_name_bytes_hex'];assert d['site_name']=='site.lck_rw_old_t';counts['typed_sites']+=1
 for r in c['data'].values():
  raw=k.read(int(r['address'],16),len(bytes.fromhex(next(v for n,v in r.items()if n.endswith('_hex')))));assert raw.hex()==next(v for n,v in r.items()if n.endswith('_hex'));counts['original_constant_spans']+=1
 actual=[]
 for at,cmd,n in commands(IMAGE.data,0):
  if cmd!=0x19 or IMAGE.data[at+8:at+24].split(b'\0')[0]!=b'__TEXT_EXEC':continue
  va,vm,off,n=struct.unpack_from('<4Q',IMAGE.data,at+24);assert n//4==c['literal_modifier_census']['words_scanned']
  for j,(w,)in enumerate(struct.iter_unpack('<I',IMAGE.data[off:off+n//4*4])):
   if w&0xffe0001f==0xd2800011 and(w>>5)&0xffff in[0x9f59,0x9d3a]:actual.append((hex(va+4*j),IMAGE.read(va+4*j,8).hex()))
 assert actual==[(r['modifier_PC'],r['bytes8_hex'])for r in c['literal_modifier_census']['rows']];counts['literal_modifier_candidates']=len(actual);counts['unresolved_modifier_candidates']=sum(r['resolution']=='unresolved_candidate'for r in c['literal_modifier_census']['rows'])
 states=c['allocation_store_candidates']['states'];assert [r['state32']for r in states]==[s for s in range(2648)if(s&0xfffffe61)==0x860];assert {r['index32']for r in states}=={0x8b4};assert pointer(k,TABLE+8*0x8b4)==c['allocation_store_candidates']['original_target_pointer'];counts['candidate_state_values']=len(states)
 for q in proof['proofs']:
  assert sha(ROOT/q['file'])==q['sha256'];s=z3.Solver();s.from_string((ROOT/q['file']).read_text());assert str(s.check())==q['result']=='unsat';counts['proofs_unsat']+=1
 assert proof['contracts_sha256']==sha(ROOT/'rw_lifecycle_contracts.json');h=Path(c['SDK_header']['path']);assert sha(h)==c['SDK_header']['sha256'];assert ''.join(h.read_text().splitlines(keepends=True)[237:254])==c['SDK_header']['text'];sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk');cmd=['clang++','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-I',str(sdk/'System/Library/Frameworks/Kernel.framework/Headers'),'-DKERNEL','-std=c++17','-O2','-S',str(ROOT/'rw_lifecycle_sdk_probe.cpp'),'-o',str(ROOT/'rw_lifecycle_sdk_probe.s')];done=subprocess.run(cmd,capture_output=True,text=True);assert done.returncode==0,(done.stdout,done.stderr);assert re.search(r'mov\s+w0, #8\b',(ROOT/'rw_lifecycle_sdk_probe.s').read_text());sdk_record={'generator_sha256':sha(Path(__file__)),'probe_sha256':sha(ROOT/'rw_lifecycle_sdk_probe.cpp'),'header_path':str(h),'header_sha256':sha(h),'command':cmd,'compile_exit':done.returncode,'stderr':done.stderr,'assembly_sha256':sha(ROOT/'rw_lifecycle_sdk_probe.s'),'signatures_checked':2,'pointer_width_bytes':8,'target_code_executed':False,'SDK_matches_kernel_build_proved':False};(ROOT/'rw_lifecycle_sdk_checks.json').write_text(json.dumps(sdk_record,indent=2)+'\n');counts['SDK_signatures']+=2
 assert [r['input']for r in p['initialize_cases']]==list(init_cases());assert [r['input']for r in p['API_prefixes']]==list(api_cases());assert [r['input']for r in p['legacy_candidates']]==list(legacy_cases(c));fresh={'initialize_cases':[],'free_validation_cases':[],'API_prefixes':[],'legacy_candidates':[]}
 for old in p['initialize_cases']:
  r=Prefix(old['input']).run();assert r==old;fresh['initialize_cases'].append(r);check_visits(k,r,counts);q=r['input'];a=0 if q['attribute32']is None else q['attribute32'];flags=(0 if a&0x10000 else 2)|(0 if a&0x20000 else 0x40);expected=bytes.fromhex('00000033000000000000')+struct.pack('<H',flags)+bytes(4);assert r['final_object16_hex']==expected.hex();ep=epoch(r,int(r['object_pointer'],16),16);assert set(ep)==set(range(16))and bytes(ep[i]for i in range(16))==expected;assert not r['models'];counts['fresh_initializer_cases']+=1;counts['initializer_visits']+=len(r['source_visits']);counts['initializer_source_written_bytes']+=16;counts['default_attribute_cases']+=int(q['attribute32']is None)
 for old in p['free_validation_cases']:
  index=old['source_initialize_case_index'];origin=fresh['initialize_cases'][index];r=Prefix(old['input'],origin).run();r['source_initialize_case_index']=index;assert r==old;fresh['free_validation_cases'].append(r);check_visits(k,r,counts);assert r['initial_object16_hex']==origin['final_object16_hex'];expected=bytes(8)+struct.pack('<I',0xdddddead)+bytes(4);assert r['final_object16_hex']==expected.hex();ep=epoch(r,int(r['object_pointer'],16),16);assert set(ep)=={*range(4),*range(8,12)}and all(expected[i]==v for i,v in ep.items());assert r['boundary']['pc']=='0xfffffe000bd06320'and [int(v,16)for v in r['boundary']['registers31'][:2]]==[GROUP,GROUP+0x14];assert not r['models'];counts['fresh_free_validation_cases']+=1;counts['free_validation_visits']+=len(r['source_visits']);counts['free_header_source_written_bytes']+=8
 for old in p['API_prefixes']:
  r=Prefix(old['input']).run();assert r==old;fresh['API_prefixes'].append(r);check_visits(k,r,counts);q=r['input'];regs=[int(v,16)for v in r['boundary']['registers31']]
  assert regs[:2]==([q['group64'],0]if q['mode']=='API_allocate'else[q['input_X0'],q['group64']]);assert not r['source_writes']and not r['models'];counts['fresh_API_prefixes']+=1;counts['API_prefix_visits']+=len(r['source_visits'])
 for old in p['legacy_candidates']:
  r=Prefix(old['input']).run();assert r==old;fresh['legacy_candidates'].append(r);check_visits(k,r,counts);q=r['input'];assert len(r['models'])==1 and not r['models'][0]['target_executed'];counts['modeled_wrapper_returns']+=1
  if q['mode']=='allocation_candidate':assert r['boundary']['pc']=='0xfffffe000a531054'and r['boundary']['registers31'][8]=='0xfffffe000a56d3c0'and not r['source_writes'];counts['fresh_allocation_candidates']+=1;counts['allocation_candidate_visits']+=len(r['source_visits'])
  else:
   cell=CELL+q['placement'];assert r['final_pointer_cell_hex']==bytes(8).hex();ep=epoch(r,cell,8);assert ep==dict.fromkeys(range(8),0);assert len(r['source_writes'])==1 and r['source_writes'][0]['pc']=='0xfffffe000a5793bc';assert int(r['models'][0]['registers8'][0],16)==int(r['object_pointer'],16);counts['fresh_cleanup_candidates']+=1;counts['cleanup_candidate_visits']+=len(r['source_visits']);counts['source_cleared_cell_bytes']+=8
 counts['all_fresh_cases']=sum(len(v)for v in fresh.values());counts['all_source_visits']=sum(len(r['source_visits'])for rows in fresh.values()for r in rows)
 (ROOT/'rw_lifecycle_replays.json').write_text(json.dumps({'scope':'Distinct fresh original prefixes and declared models; no native lock/heap/lifetime proof.','generator_sha256':sha(Path(__file__)),**fresh,'native_target_executed':False},indent=2)+'\n');deps.update(['rw_lifecycle_contracts.json','rw_lifecycle_profiles.json','rw_lifecycle_proofs.json','rw_lifecycle_sdk_probe.cpp']);out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'fresh_replays_sha256':sha(ROOT/'rw_lifecycle_replays.json'),'SDK_checks_sha256':sha(ROOT/'rw_lifecycle_sdk_checks.json'),'all_checks_pass':True,'native_target_executed':False,'heap_backend_executed':False,'native_lock_lifetime_proved':False,'cached_cell_publication_proved':False,'full_goal_complete':False};(ROOT/'rw_lifecycle_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
