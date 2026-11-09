#!/usr/bin/env python3
"""Fresh source/import/GOT/header/proof/plist readback for RPC700 leads.

No native target, IPC, IOKit, loader, synchronization or IDB operation.
O(total pinned source bytes + imports + GOT + instructions) verification;
two timeout-bounded local solvers and compile-only SDK assertions.
"""
import collections,hashlib,json,plistlib,re,struct,subprocess
from pathlib import Path
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import commands,macho,string
from bootpolicy_cache_reader import Cache,Dylib
ROOT=Path(__file__).resolve().parent
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def main():
 c=json.loads((ROOT/'rpc700_namespace_contracts.json').read_text());assert c['generator_sha256']==sha(ROOT/'recover_rpc700_namespace.py');deps={'rpc700_namespace_contracts.json','recover_rpc700_namespace.py','kernel_native_reader.py','resolve_kernel_collection_interfaces.py','bootpolicy_cache_reader.py','rpc700_host_special_ports.h','rpc700_host_constants.c'}
 for n,h in c['dependencies'].items():assert sha(ROOT/n)==h
 k=Kernel();assert c['kernel_collection_sha256']==k.sha256 and c['kernel_uuid']==k.kernel['uuid'];counts=collections.Counter()
 for f in c['kernel_functions']:assert k.function(int(f['start'],16))==f;counts['kernel_functions']+=1
 assert k.symbols([int(f['start'],16)for f in c['kernel_functions']])==c['kernel_exact_symbols'];assert [e['name']for v in c['kernel_exact_symbols'].values()for e in v]==['_host_get_special_port','_host_priv_self'];counts['exact_kernel_symbol_bindings']=2
 getter={e['ea']:(e['mnemonic'],e['operands'])for e in c['kernel_functions'][0]['instructions']}
 for pc,want in{'0xfffffe000bcf25b4':('sub','w8, w2, #0x25'),'0xfffffe000bcf25b8':('cmn','w8, #0x24'),'0xfffffe000bcf25bc':('b.lo','#0xfffffe000bcf26a8'),'0xfffffe000bcf25f0':('ubfiz','x9, x22, #3, #0x20'),'0xfffffe000bcf2600':('movk','x16, #0x2bad, lsl #48'),'0xfffffe000bcf2614':('autda','x16, x17'),'0xfffffe000bcf2678':('bl','#0xfffffe000bcd00bc'),'0xfffffe000bcf2680':('mov','w0, #0'),'0xfffffe000bcf2684':('str','x8, [x21]')}.items():assert getter[pc]==want
 for e in c['proofs']:
  path=ROOT/e['file'];assert sha(path)==e['sha256'];run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat'and not run.stderr;counts['proofs_unsat']+=1;deps.add(path.name)
 h=c['SDK_header'];assert sha(Path(h['path']))==sha(ROOT/h['snapshot'])==h['sha256'];assert sha(ROOT/'rpc700_host_constants.c')==h['probe_sha256'];run=subprocess.run(['clang','-target','arm64e-apple-macos13.0','-isysroot','/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk','-fsyntax-only',str(ROOT/'rpc700_host_constants.c')],capture_output=True,text=True);assert run.returncode==0;counts['SDK_compile_exit']=0
 for row in c['plists']:
  p=Path(row['path']);raw=p.read_bytes();assert sha(p)==row['sha256']and raw.hex()==row['raw_hex']and plistlib.loads(raw)==row['parsed'];counts['plists']=counts['plists']+1
  if 'managedappdistribution'in p.name:assert all(not isinstance(v,dict)or'HostSpecialPort'not in v for v in row['parsed']['MachServices'].values())
 for row in c['candidate_binaries']:
  raw=Path(row['source_path']).read_bytes();assert hashlib.sha256(raw).hexdigest()==row['source_sha256']and len(raw)==row['source_size_bytes'];a=row['selected_slice'];b=raw[a['offset']:a['offset']+a['size_bytes']];assert hashlib.sha256(b).hexdigest()==a['sha256'];m=macho(b,0,'readback');assert m['uuid']==row['uuid']and m['sections']==row['sections'];loads=[];imports=[];parameters=None
  for at,cmd,n in commands(b,0):
   if cmd in(0xc,0x80000018,0x8000001f,0x80000023,0x20):loads.append(string(b,at+struct.unpack_from('<I',b,at+8)[0]))
   if cmd==0x80000034:
    fo,sz=struct.unpack_from('<II',b,at+8);v,st,im,sy,nim,fmt,sf=struct.unpack_from('<7I',b,fo);parameters=(fo,im,sy,nim,fmt)
  assert loads==row['loads'];fo,im,sy,nim,fmt=parameters
  for j in range(nim):
   iw=struct.unpack_from('<I',b,fo+im+(4 if fmt==1 else 8)*j)[0];ordinal=iw&255;ordinal=ordinal-256 if ordinal&128 else ordinal;imports.append({'ordinal':j,'name':string(b,fo+sy+(iw>>9)),'library_ordinal':ordinal,'library':loads[ordinal-1]if 0<ordinal<=len(loads)else'special ordinal'})
  assert imports==row['imports'];assert not row['direct_Mach_host_MIG_imports'];assert not[e for e in imports if re.search('host_(get|set)|mach_|mig_',e['name'],re.I)];counts['candidate_import_records']+=len(imports)
  expected=[]
  for pos in range(8,len(b)-12,8):
   start,end,maximum=struct.unpack_from('<3I',b,pos)
   if 0<=start<=700<end<=4796 and 36<=maximum<=1048576:expected.append((pos-8,start,end,maximum))
  assert expected==[(e['header_file_offset'],e['start'],e['end'],e['max_reply_bytes'])for e in row['MIG700_header_shape_candidates']]
  for e in row['MIG700_header_shape_candidates']:
   assert e['schema_rejections']and not e['passes_common_header_gates']and not e['verified_MIG_table'];assert hex(struct.unpack_from('<Q',b,e['header_file_offset'])[0])==e['first_pointer_hex'];counts['rejected_header_shapes']+=1
  counts['candidate_slices']+=1
 assert c['positive_control']['source_sha256']==sha(Path('/Users/___/Downloads/zut/fairplayd.arm64e'));assert any(e.get('address')=='0x1010381c0'and e['passes_common_header_gates']for e in c['positive_control']['candidates']);counts['known_MIG_positive_controls']=1
 cache=Cache();assert c['cache_uuid']==cache.uuid;d=Dylib(cache,c['framework']['path']);assert d.uuid==c['framework']['uuid']and len(d.functions)==c['framework']['functions'];allowed_got={a for s in d.sections if s['name']in['__got','__auth_got']for a in range(s['address'],s['address']+s['size'],8)};assert {int(e['address'],16)for e in c['framework']['GOT_records']}==allowed_got
 targets=set()
 for path in['/usr/lib/system/libsystem_kernel.dylib','/usr/lib/system/libsystem_c.dylib','/usr/lib/system/libxpc.dylib']:
  lib=Dylib(cache,path);targets.update(v['address']for n,v in lib.exports.items()if re.search(r'^_(host_|mach_|mig_|xpc_connection_)',n))
 for e in c['framework']['GOT_records']:
  a=int(e['address'],16)
  if e.get('null'):assert cache.read(a,8)==bytes(8)
  else:
   actual=cache.pointer(a);assert all(actual[n]==e[n]for n in actual);assert not e['selected_export_matches']and int(e['target'],16)not in targets
  counts['framework_GOT_records']+=1
 for f in c['cache_files_hashed']:assert sha(Path(f['path']))==f['sha256']and Path(f['path']).stat().st_size==f['size_bytes'];counts['cache_files_hashed']+=1
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in sorted(deps)},'verified_counts':dict(counts),'receiver_identified':False,'native_target_executed':False,'native_port_objects_observed':False,'SDK_label_is_native_registration_proof':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'rpc700_namespace_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(counts)),flush=True)
if __name__=='__main__':main()
