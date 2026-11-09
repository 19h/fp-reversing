#!/usr/bin/env python3
"""Static register-residue lineage; never imports or runs a target probe."""
import hashlib,json,capstone
from pathlib import Path
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,sha,h,FLAGS
P='daemon_helper_result_residue'
SCOPE='Selected source X5 liveness from helper tail to frozen malloc-entry snapshot, source output relation and low36 recovery. No full generator algorithm, native execution, memory noninterference or daemon-kext pairing.'
RANGES={
 'last_X5_definition':(0x100449e38,0x100449e3c),
 'helper_live':(0x100449e3c,0x10044a3e0),
 'population_postcall':(0x1006f0b28,0x1006f0b60),
 'adapter':(0x100752360,0x1007523ac),
 'typed_root':(0x100828290,0x1008282d0),
 'constructor_entry':(0x100700d80,0x100700df0),
 'constructor_guard':(0x10083c564,0x10083c604),
 'node_allocation_precall':(0x1006958b0,0x10069592c)}
def norm(r):return 'x'+r[1:]if r.startswith('w')and r[1:].isdigit()else {'fp':'x29','lr':'x30'}.get(r,r)
def capture(a,z):
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 b=IMAGE.read(a,z-a);ii=list(dc.disasm(b,a));assert len(ii)*4==len(b)
 rows=[]
 for i in ii:
  r,w=i.regs_access();rows.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'reads':sorted({norm(i.reg_name(v))for v in r}),'writes':sorted({norm(i.reg_name(v))for v in w})})
 return {'start':hex(a),'end':hex(z),'bytes':b.hex(),'sha256':h(b),'instructions':rows}
def build():
 parent=json.loads((ROOT/'daemon_scalar_field_population_source.json').read_text());ctor=json.loads((ROOT/'daemon_constructor_inputs_source.json').read_text())
 assert sha(SOURCE)==parent['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={n:capture(a,z)for n,(a,z)in RANGES.items()}
 original=[]
 for file,frags in [('daemon_scalar_field_population_source.json',{'helper':parent['helper_complete'],**parent['fragments']}),('daemon_constructor_inputs_source.json',ctor['fragments'])]:
  for n,f in frags.items():
   b=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(b))==b;original.append({'file':file,'range':n,'bytes_checked':len(b),'sha256':h(b)})
 assert fs['last_X5_definition']['instructions'][0]['operands']=='x5, x5, x7, lsl #1'
 no5=[i['ea']for n,f in fs.items()if n!='last_X5_definition'for i in f['instructions']if 'x5'in i['writes']];assert not no5
 helper=fs['helper_live']['instructions'];defs11=[i for i in helper if 'x11'in i['writes']];assert defs11[-1]['ea']=='0x100449fa8'and defs11[-1]['operands']=='x11, x5, x17, lsl #36'
 projection=[defs11[-1]]+[i for i in helper if 0x10044a3a4<=int(i['ea'],16)<=0x10044a3b4];assert len(projection)==6
 allowed={'helper_live':['retab'],'population_postcall':['braa'],'adapter':['braa'],'typed_root':['braa'],'constructor_entry':['braa'],'constructor_guard':['braa'],'node_allocation_precall':['blraa']}
 controls={}
 for n,expected in allowed.items():
  controls[n]=[{'ea':i['ea'],'mnemonic':i['mnemonic'],'operands':i['operands']}for i in fs[n]['instructions']if i['mnemonic'].startswith(('b.','cb','tb'))or i['mnemonic']in('b','bl','br','blr','braa','brab','blraa','blrab','ret','retab','retaa','svc','hvc','smc')]
  assert [i['mnemonic']for i in controls[n]]==expected
  assert controls[n][0]['ea']==fs[n]['instructions'][-1]['ea']
 # Verify parent bindings against the original image/fixup catalog; do not infer targets from modifiers alone.
 pointers=[]
 for file,obj in [('daemon_scalar_field_population_source.json',parent),('daemon_constructor_inputs_source.json',ctor)]:
  for r in obj.get('pointer_records',obj.get('selected_pointer_records',[])):
   a=int(r['slot'],16);assert IMAGE.read(a,8).hex()==r['raw_bytes']and FIXUPS[a]==r['fixup'];pointers.append({'source':file,**r})
 profiles=json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles'];out=[]
 expected=[('0x1006f0b5c','0x100752360'),('0x1007523a8','0x100828290'),('0x1008282cc','0x100700d80'),('0x100700dec','0x10083c564'),('0x10083c600','0x1006958b0')]
 for old in parent['retained_profiles']:
  p=next(p for p in profiles if p['label']==old['label']);assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed'];ev=p['pac_bypasses'];j=next(j for j,e in enumerate(ev)if e.get('site')=='0x1006f0b24'and e.get('target')=='0x100444dfc');seq=ev[j:j+9]
  assert [(e['site'],e['instruction'])for e in seq[1:3]]==[('0x100444dfc','pacibsp'),('0x10044a3dc','retab')]
  assert [(e['site'],e['target'])for e in seq[3:8]]==expected
  assert seq[8]['site']=='0x100695928'
  nodes=[c for c in p['calls']if c.get('return_pc')=='0x10069592c'];snap=nodes[2];assert snap==old['third_node_allocation']and snap['name']=='libSystem/_malloc'and len(snap['args'])==8
  r=int(snap['args'][5],16);low36=(r^0xc0eaaa2272eb67c0)&((1<<36)-1);wire=((r^0xc0eaaa2272eb67c0^0x55919137)&0xffffffff).to_bytes(4,'big').hex();assert wire==old['wire_field']['payload_hex']and low36==0x151633a82
  out.append({'label':p['label'],'events':seq,'malloc_entry_snapshot':snap,'X5_residue_u64':hex(r),'derived_helper_output_low36':hex(low36),'derived_wire_payload_hex':wire,'recorded_wire_field':old['wire_field'],'native_evidence':False,'helper_result_is_inferred_not_direct_snapshot':True})
 hook=ROOT/'probe_arcade_subscription.py';lines=hook.read_text().splitlines();assert 'args=[self.reg(i) for i in range(8)]'in lines[79]and "n=args[0]"in lines[164]
 deps=['daemon_scalar_field_population_source.json','daemon_scalar_field_population_checks.json','daemon_constructor_inputs_source.json','daemon_constructor_inputs_checks.json','arcade_subscription_profiles.json','probe_arcade_subscription.py','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt']
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'X5_liveness_intervals':7,'X5_clobbers_in_intervals':0,'scalar_projection_instructions':6,'original_pointer_records_recaptured':len(pointers),'prior_ranges_recaptured':len(original),'prior_bytes_recaptured':sum(r['bytes_checked']for r in original),'frozen_profiles':len(out),'recovered_result_bits':36,'unresolved_result_bits':28}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'scalar_projection':projection,'control_ledger':controls,'X5_clobbers':no5,'original_pointer_records':pointers,'prior_recaptures':original,'profiles':out,'snapshot_producer':{'path':str(hook),'sha256':sha(hook),'entry_capture_lines_80_82':lines[79:82],'malloc_size_lines_165_167':lines[164:167],'scope':'Read-only historical generator inspection; not imported or run. args lists raw X0..X7; malloc only consumes X0.'},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
