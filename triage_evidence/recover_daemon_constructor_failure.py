#!/usr/bin/env python3
"""Static constructor cleanup/early-return contracts and explicit prior-slot erratum."""
import json,re,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,selected,binding,sha,h,FLAGS
P='daemon_constructor_failure'
SCOPE='Conditional constructor early rejection, candidate-buffer/node retirement, full-X6 marker preservation and saved continuation return. Static owner-read boundary and allocator slot-label erratum are explicit. Frozen successful profiles observe no failure cleanup. Native allocator effects, phase/owners/PAC and daemon-kext transport remain unproved.'
BLOCKS={'entry':0x100700d80,'guard':0x10083c564,'node_alloc':0x1006958b0,'record_alloc':0x100948a8c,'failure':0x1008c3528,'free_buffer':0x10078c384,'free_node':0x1006b794c,'early_return':0x10076de60,'invalid_tag_join':0x100544fd0,'lookup_status':0x100742a30,'lookup_miss':0x1009a0b64,'lookup_found':0x10069a114}
INDICES=[0xab69,0xabaa,0x79f1,0xc1cd,0xa1c8,0xa1cb,0xc714,0xc766,0xa7f7,0xa7fb,0x3c99,0x53c3,0xcc08,0x72b4,0x7278]
def build():
 fs={};writes={};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f;rr=set()
  for i in dc.disasm(bytes.fromhex(f['bytes']),a):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  writes[n]=sorted(rr)
 ptr=[]
 for ix in INDICES:
  a=TABLE+8*ix;ptr.append({'index':hex(ix),'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]})
 banks=[]
 for role,key,add,pc in [('candidate_buffer',0x86,0xcbb0,0x10078c3f0),('candidate_node',0x9a,0xcb23,0x1006b79a4)]:
  l,r=0x101031da0,0x100e99900;b=selected(l,r,key,add,TABLE,0);lb,rb=IMAGE.read(l,256),IMAGE.read(r,256);vv=[i^rb[lb[i]^key]for i in range(256)];assert len(set(vv))==1 and b['target']=='libSystem/_free'and b['slot']=='0x10109ff30'
  ins=list(CS.disasm(IMAGE.read(pc-4,8),pc-4));assert ins[0].op_str=='x17, #0x46a2'and ins[1].mnemonic=='blraa'
  b.update(role=role,site=hex(pc),left_bytes=lb.hex(),right_bytes=rb.hex(),key_u8=key,additive_u32=add,results_256=vv,left_frame_slot='0x5f0',right_frame_slot='0x5e0',left_register='x24',right_register='x23',modifier_u16=0x46a2);banks.append(b)
 old=json.loads((ROOT/'daemon_constructor_inputs_source.json').read_text());assert old['allocation_banks'][1]['role']=='record'and old['allocation_banks'][1]['frame_bank_pointer_slots']==['0x5f0','0x960']
 ins=next(i for i in fs['record_alloc']['instructions']if i['ea']=='0x100948bbc');assert ins['mnemonic']=='ldr'and ins['operands']=='x10, [sp, #0x968]'
 erratum={'historical_file':'daemon_constructor_inputs_source.json','historical_json_pointer':'/allocation_banks/1/frame_bank_pointer_slots/0','historical_value':'0x5f0','correct_value':'0x968','source_instruction':ins,'scope':'The old frame-slot label is wrong; bank arrays, exhaustive numeric selection and original malloc binding remain conditional and unchanged. Historical JSON/script are preserved; the human report is corrected and this ledger supersedes that one metadata label.'}
 rec=[]
 for fn in ['daemon_typed_scalar_source.json','daemon_constructor_lookup_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'file':fn,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 live=[]
 for name,a,z,regs in [('failure',0x1008c352c,0x1008c3590,[25]),('free_buffer',0x10078c384,0x10078c3f0,[0,20,21,23,24,25]),('free_buffer',0x10078c3f4,0x10078c404,[19,20,21,22,23,24,25]),('free_node',0x1006b794c,0x1006b79a4,[19,23,24,25])]:
  rr=set()
  for i in dc.disasm(IMAGE.read(a,z-a),a):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  assert not{p+str(r)for r in regs for p in('x','w')}&rr;live.append({'fragment':name,'start':hex(a),'end':hex(z),'preserved_registers':regs,'written_registers':sorted(rr)})
 pp=[]
 for p in json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles']:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed'];ev=p['pac_bypasses'];targets={n:sum(e.get('target')==hex(BLOCKS[n])for e in ev)for n in ['failure','free_buffer','free_node']};calls={hex(pc):sum(e.get('site')==hex(pc)for e in ev)for pc in[0x10078c3f0,0x1006b79a4]};assert set(targets.values())=={0}and set(calls.values())=={0};nr=[c for c in p['calls']if c['return_pc']=='0x10069592c'];br=[c for c in p['calls']if c['return_pc']=='0x100948bfc'];assert len(nr)==len(br)==5 and all(int(c['result'],16)!=0 for c in nr+br)
  pp.append({'label':p['label'],'cleanup_target_occurrences':targets,'cleanup_call_occurrences':calls,'node_result_pointers':[c['result']for c in nr],'buffer_result_pointers':[c['result']for c in br],'native_evidence':False})
 assert len(pp)==12
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in ptr:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 deps=['daemon_constructor_inputs_source.json','daemon_constructor_inputs_checks.json','recover_daemon_constructor_inputs.py','daemon_typed_scalar_source.json','daemon_typed_scalar_checks.json','daemon_constructor_lookup_source.json','daemon_constructor_lookup_checks.json','arcade_subscription_profiles.json','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt']
 return{'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'register_write_sets':writes,'pointer_records':ptr,'retirement_banks':banks,'free_binding':binding(0x10109ff30),'prior_recaptures':rec,'liveness_intervals':live,'metadata_erratum':erratum,'retained_profiles':pp,'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},'verified_source_counts':{'fragments':len(fs),'instructions':sum(len(f['instructions'])for f in fs.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(ptr),'bank_inputs_checked':512,'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec),'liveness_intervals':len(live),'retained_profiles':len(pp),'node_results_nonnull':60,'buffer_results_nonnull':60,'cleanup_entries_observed':0,'metadata_labels_corrected':1},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
