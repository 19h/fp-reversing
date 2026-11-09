#!/usr/bin/env python3
"""Capture original terminal A70 output/status contracts, without executing target code.
O(image+fixups+retained visits+source bytes) time/space. Historical cases are locators.
"""
import json,re,subprocess
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,qword,block,verify_original_fixups,binding,SDK,sha,h,FLAGS
P='daemon_xpc_error_outputs'
FIXED={'prologue':(0x10061a2d0,0x10061a328),'xpc_prologue':(0x100b27b78,0x100b27b9c),'save_record':(0x1004c244c,0x1004c24c0),
       'xpc_cells':(0x100a86d08,0x100a86d18),'xpc_return':(0x100a86e40,0x100a86e74),
       'adapter_return':(0x100660230,0x100660254),'guard_failure':(0x100528e24,0x100528e28),
       'adapter_budget_init':(0x10066016c,0x100660180),'core_budget_update':(0x10061a458,0x10061a464)}
BLOCKS={'a70_head':0x100592ebc,'status_gate':0x1007fb760,'clear_outputs':0x10057a770,
        'result_return':0x100528dd8,'guard_stub':0x100e2aad0}
EDGES=[('nonmarker','status_gate',0x4302,0x10057a770),('marker','status_gate',0x4314,0x100528dd8),
       ('after_clear','clear_outputs',0x19a3,0x100528dd8)]
PRIOR=['daemon_xpc_core_bridge_source.json','daemon_xpc_reply_lifecycle_source.json','daemon_core_dispatch_source.json']
PROFILES=['daemon_client_object_profiles.json','daemon_vm_cleanup_retire_profiles.json']
SCOPE='Original terminal A70 marker/nonmarker partition, caller-owned output cells, result-before-canary ordering and conditional XPC status/no-data join. Output-cell consumption across the caller SP adjustment requires delta zero; the full budget write history is unproved. Historical allocation-failure cases are retained private models, not new source executions or native XPC reachability. Successful output writers/ownership, native policy/return/PAC/port identities/delivery and daemon-kext exchange remain unknown.'

def capture(a,z):
 bb=IMAGE.read(a,z-a);ii=list(CS.disasm(bb,a));assert len(bb)==4*len(ii)
 return {'start':hex(a),'end':hex(z),'bytes':bb.hex(),'sha256':h(bb),
         'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}

def build():
 fragments={n:capture(a,z)for n,(a,z)in FIXED.items()}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']in('braa','retab');f['sha256']=h(bytes.fromhex(f['bytes']));fragments[n]=f
 edges=[];slots={0x1010b1d00,0x1010b1e18,0x1010b1e28}
 for name,source,ix,target in EDGES:
  slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');ii=fragments[source]['instructions'];mod=int(ii[-2]['operands'].split('#')[1],0)
  assert qword(slot)==target and w>>63 and (w>>32&65535)==mod and not(w>>48&1)and not(w>>49&3)
  slots.add(slot);edges.append({'role':name,'source':source,'site':ii[-1]['ea'],'index':hex(ix),'slot':hex(slot),'target':hex(target),'modifier_u16':mod,'pointer_word':hex(w)})
 recaptures=[]
 def walk(o,fn,path=''):
  if isinstance(o,dict):
   data=o.get('bytes',o.get('bytes_hex'));a=o.get('start')
   if isinstance(data,str)and isinstance(a,str)and a.startswith('0x'):
    bb=bytes.fromhex(data);assert IMAGE.read(int(a,16),len(bb))==bb
    recaptures.append({'file':fn,'path':path,'start':a,'bytes_checked':len(bb),'sha256':h(bb)})
   for k,v in o.items():walk(v,fn,path+'/'+k)
  elif isinstance(o,list):
   for j,v in enumerate(o):walk(v,fn,path+'/'+str(j))
 for fn in PRIOR:walk(json.loads((ROOT/fn).read_text()),fn)
 retained=[];unique={};case_count=0;visits=0
 for fn in PROFILES:
  s=json.loads((ROOT/fn).read_text());assert s['source_sha256']==sha(SOURCE)and not s['native_target_executed']
  for index,c in enumerate(s['cases']):
   case_count+=1;b=c['boundary']
   if b['pc']!='0x10057a774':continue
   assert b['kind']=='before_unmapped_owner_write'and not c['fixture_PC_transitions']
   regs=b['registers31'];assert int(regs[8],16)==0x19a3 and int(regs[19],16)==0x6cf4
   assert int(regs[6],16)==(0x74c29d85 if fn==PROFILES[0]else 0x74c29d69)
   F=int(b['SP'],16);protected=[(F+o,F+o+8)for o in(0x580,0x1a30,0x7098)]
   overwrites=[x for x in c['source_writes']if any(int(x['address'],16)<z and int(x['address'],16)+x['size_bytes']>a for a,z in protected)]
   assert not overwrites
   for v in c['source_visits']:
    assert v['image']=='daemon';pc=int(v['pc'],16);bb=bytes.fromhex(v['bytes_hex']);assert len(bb)==4 and IMAGE.read(pc,4)==bb
    assert pc not in unique or unique[pc]==bb.hex();unique[pc]=bb.hex();visits+=1
   retained.append({'file':fn,'case_index':index,'configuration':c['configuration'],'historical_boundary_PC':b['pc'],
      'historical_raw_status_u32':regs[6],'historical_W8':regs[8],'historical_W19':regs[19],
      'historical_source_visits_checked':len(c['source_visits']),'watched_frame_cells_unmodified_in_retained_interval':True,
      'XPC_pointer_substitution_or_target_execution_performed':False})
 assert len(retained)==64
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for a in slots:assert fresh[a]==FIXUPS[a]['line']
 deps=PRIOR+PROFILES+['daemon_xpc_core_bridge_checks.json','daemon_xpc_reply_lifecycle_checks.json','daemon_client_object_contracts.json','daemon_vm_cleanup_contracts.json','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py','recover_daemon_xpc_core_bridge.py']
 headers=[SDK/'usr/include/stdint.h',SDK/'usr/include/stddef.h',SDK/'usr/include/xpc/xpc.h']
 return {'generator_sha256':sha(__file__),'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'static_scope':SCOPE,
  'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fragments,'branches':edges,
  'imports':[binding(a)for a in sorted(slots)if isinstance(FIXUPS[a]['target'],str)],
  'selected_pointer_records':[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)],
  'original_pointer_checks':verify_original_fixups([a for a in slots if FIXUPS[a]['kind'].startswith('auth-')]),
  'fixup_reference':{'command':cmd,'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh),'selected_lines':{hex(a):fresh[a]for a in sorted(slots)}},
  'prior_source_recaptures':recaptures,'historical_case_boundaries':retained,
  'historical_original_instructions':[{'ea':hex(a),'bytes':bb}for a,bb in sorted(unique.items())],
  'SDK_headers':[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in headers],
  'inspection_tools':[{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')}],
  'verified_source_counts':{'fragments':len(fragments),'instructions':sum(len(f['instructions'])for f in fragments.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'branch_bindings':len(edges),'selected_pointer_records':len(slots),'fixup_catalog_memberships_compared':len(fresh),'prior_source_ranges_checked':len(recaptures),'prior_source_bytes_checked':sum(x['bytes_checked']for x in recaptures),'historical_cases_inspected':case_count,'historical_boundaries_checked':len(retained),'historical_instruction_visits_recaptured':visits,'historical_unique_instructions_recaptured':len(unique)},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
