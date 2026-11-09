#!/usr/bin/env python3
"""Static constructor lookup/commit and frozen miss-path capture."""
import json,re,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,selected,binding,sha,h,FLAGS
P='daemon_constructor_lookup'
SCOPE='Conditional first-identifier lookup, address-mask word decoder, miss append and source-only matched-node replacement/retirement/return. Historical private profiles exercise misses only. Native phase/owners/bank roots/PAC/authorization/transport and complete type admission remain unproved.'
BLOCKS={'entry':0x1006fd1b8,'nonnull':0x10070d1f0,'next':0x100697188,'candidate':0x100914e3c,'prepare_decoder':0x1006f6bf0,'decode':0x100800004,
 'compare':0x100615a1c,'advance':0x1005bb1b0,'publish':0x100914a10,'mediator':0x1006c5c2c,'returned':0x1008351c8,'status_gate':0x100742a30,
 'miss_gate':0x1009a0b64,'found_gate':0x10069a114,'replace':0x100873ecc,'prev_patch':0x1008d776c,'next_gate':0x100850478,'next_patch':0x1005d2758,
 'head_gate':0x10072d140,'head_patch':0x1006e4168,'tail_gate':0x100843e64,'tail_patch':0x10075118c,'retire':0x100831528,'free_buffer':0x1006c1034,
 'free_node':0x100747e28,'early_return':0x10076de60,'append_gate':0x1006f0208,'append_empty':0x1004def68,'append_nonempty':0x10069a4a0}
INDICES=[0x12fa,0xc157,0xc1ca,0x5e28,0x57d4,0x582e,0x2520,0x8c3f,0xc8,0xa924,0xa93d,0x8209,0x36a5,0x72b4,0x7278,0x3c99,0x3cc1,0xbea6,0x4308,0x434f,0x9ada,0x9add,0x5583,0x6b95,0x6b9b,0x9fbf,0xc43c,0xc3be,0xc3d2,0xb8dc,0x79f1,0x9c85,0x9ca7,0xcc08]
def retained():
 rows=[]
 for p in json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles']:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed']
  ev=p['pac_bypasses'];starts=[j for j,e in enumerate(ev)if e.get('target')=='0x1006fd1b8'and e['site']=='0x1005ae804'];assert len(starts)==5;episodes=[]
  for j in starts:
   z=next(k for k in range(j+1,len(ev))if ev[k]['site']=='0x10076de68');seq=ev[j:z+1]
   assert sum(e['site']=='0x100914e80'for e in seq)==sum(e['site']=='0x100800790'for e in seq)
   compares=[e for e in seq if e['site']=='0x100615a68'];assert all(e['target']=='0x1005bb1b0'for e in compares)
   assert sum(e['site']=='0x100914a2c'for e in seq)==1
   assert sum(e['site']=='0x1006f0248'for e in seq)==1
   assert not any(e['site']in('0x1006c10ac','0x100747e84')for e in seq)
   assert all(e['authentication']=='bypassed in private synthetic model'for e in seq)
   episodes.append({'first_event_index':j,'last_event_index':z,'candidate_comparisons':len(compares),'events':seq})
  assert[e['candidate_comparisons']for e in episodes]==[0,1,2,0,1]
  aj=[j for j,e in enumerate(ev)if e.get('target')=='0x1006fd1b8'and e['site']!='0x1005ae804'];assert len(aj)==1;j=aj[0];z=next(k for k in range(j+1,len(ev))if ev[k]['site']=='0x1006c5c30');seq=ev[j:z+1]
  cc=[e for e in seq if e['site']=='0x100615a68'];assert len(cc)==2 and all(e['target']=='0x1005bb1b0'for e in cc)
  rows.append({'label':p['label'],'lookup_episodes':episodes,'candidate_comparisons':4,'other_lookup_episode':{'first_event_index':j,'last_event_index':z,'events':seq,'candidate_comparisons':2},'replacement_occurrences':0,'native_evidence':False})
 assert len(rows)==12;return rows
def build():
 fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;writes={}
 for n,f in fs.items():
  rr=set()
  for i in dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  writes[n]=sorted(rr)
 assert not {'x1','w1','x4','w4','x16','w16'}&set(writes['prepare_decoder'])
 assert not any(i['mnemonic']in('bl','blr','blraa','blrab')for i in fs['prepare_decoder']['instructions'])
 ptr=[]
 for ix in INDICES:
  a=TABLE+8*ix;ptr.append({'index':hex(ix),'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]})
 banks=[]
 for role,l,r,key,add,pc,slots in[('old_buffer',0x100e99700,0x100f4e190,0x81,0xcbc0,0x1006c10ac,['0x870','0x868']),('old_node',0x100e99800,0x100f4e290,0x61,0xcbef,0x100747e84,['0x5d0','0x5d8'])]:
  b=selected(l,r,key,add,TABLE,0);ll,rr=IMAGE.read(l,256),IMAGE.read(r,256);v=[i^rr[ll[i]^key]for i in range(256)];assert len(set(v))==1 and b['target']=='libSystem/_free'and b['slot']=='0x10109ff30'
  ii=list(CS.disasm(IMAGE.read(pc-4,8),pc-4));assert ii[0].op_str=='x17, #0x46a2'and ii[1].mnemonic=='blraa'
  b.update(role=role,site=hex(pc),left_bytes=ll.hex(),right_bytes=rr.hex(),key_u8=key,additive_u32=add,results_256=v,frame_bank_pointer_slots=slots,modifier_u16=0x46a2);banks.append(b)
 rec=[]
 for fn in['daemon_constructor_inputs_source.json','daemon_header_codec_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'file':fn,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in ptr:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 pp=retained();deps=['daemon_constructor_inputs_source.json','daemon_constructor_inputs_checks.json','daemon_header_codec_source.json','daemon_header_codec_checks.json','daemon_payload_codec_checks.json','arcade_subscription_profiles.json','validate_daemon_constructor_inputs.py','validate_daemon_header_codec.py','daemon_receive_fixups.txt','daemon_import_bindings.py']
 return{'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'register_write_sets':writes,'pointer_records':ptr,'retirement_banks':banks,'free_binding':binding(0x10109ff30),'prior_recaptures':rec,'retained_profiles':pp,
  'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},
  'verified_source_counts':{'fragments':len(fs),'instructions':sum(len(f['instructions'])for f in fs.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(ptr),'bank_inputs_checked':512,'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec),'retained_profiles':12,'lookup_episodes':60,'candidate_comparisons':48,'other_lookup_episodes':12,'other_candidate_comparisons':24,'replacement_occurrences':0},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
