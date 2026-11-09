#!/usr/bin/env python3
"""Original typed-constructor routing and u64 writer; static and frozen evidence only."""
import json,re,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,sha,h,FLAGS
P='daemon_typed_scalar'
SCOPE='Selected-phase full u16 constructor discriminator partition and scalar extent gates; source-only BE64 writer, address-mask components and saved-value/return join. Frozen profiles exercise u32/span only. Native phase, owner, allocator, PAC, failure cleanup and daemon-kext transport remain unproved.'
BLOCKS={'key_setup':0x1008ecb78,'word':0x100546c90,'after_header':0x1004f4bc4,'u32_class':0x100609b18,'u32_length':0x1005c96d4,'span_class':0x1005e72c4,'span_tag':0x10058ac54,'u64_class':0x100546360,'u64_length':0x10079d560,'u64_call':0x1004cdd70,'u64_writer':0x1005a2c2c,'failure_gate':0x100544fd0,'failure_entry':0x1008c3528,'u32_call':0x100534f24,'common_finish':0x1005ae7a0}
INDICES=[0x6f0f,0x6f57,0xc0cd,0x53c3,0x24aa,0x24e6,0x53aa,0xc864,0xcb61,0xa1c8,0x7d2d,0x134c,0x3c99,0x64ae]
KEYREGS={8,9,10,11,12,13,15,28,30}
def constants(fs):
 groups=[]
 for n,reg,a in [('key_setup',r,None)for r in sorted(KEYREGS)]+[('word',20,0x100546fa0)]:
  ii=fs[n]['instructions'];hits=[j for j,i in enumerate(ii)if i['mnemonic']=='mov'and i['operands'].startswith('x'+str(reg)+', #')and(a is None or int(i['ea'],16)==a)];assert len(hits)==1
  ss=ii[hits[0]:hits[0]+4];assert all(i['mnemonic']=='movk'and i['operands'].startswith('x'+str(reg)+', #')for i in ss[1:]);v=int(ss[0]['operands'].split('#')[1],0)
  for i in ss[1:]:parts=i['operands'].split('#');imm=int(parts[1].split(',')[0],0);shift=int(parts[2],0);v=(v&~(65535<<shift))|(imm<<shift)
  groups.append({'fragment':n,'register':reg,'start':ss[0]['ea'],'end':hex(int(ss[-1]['ea'],16)+4),'value_u64':hex(v),'instructions':ss})
 return groups
def known_states(fs,groups):
 known={g['register']:int(g['value_u64'],16)for g in groups};states={};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for ins in dc.disasm(bytes.fromhex(fs['u64_writer']['bytes']),BLOCKS['u64_writer']):
  states[hex(ins.address)]={str(k):hex(v)for k,v in sorted(known.items())};op=ins.op_str.split(', ');old=dict(known)
  for rr in ins.regs_access()[1]:
   name=ins.reg_name(rr)
   if re.fullmatch('[xw][0-9]+',name):known.pop(int(name[1:]),None)
  if ins.mnemonic=='mov'and len(op)==2 and op[0][0]in'xw'and op[1].startswith('#'):known[int(op[0][1:])]=int(op[1][1:],0)&((1<<(32 if op[0][0]=='w'else 64))-1)
  if ins.mnemonic=='movk':
   r=int(op[0][1:]);shift=int(op[2].split('#')[1],0)
   if r in old:known[r]=(old[r]&~(65535<<shift))|(int(op[1][1:],0)<<shift)
 return states

def build():
 fs={};writes={};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in BLOCKS.items():
  f=block(a,0x5000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f;rr=set()
  for i in dc.disasm(bytes.fromhex(f['bytes']),a):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  writes[n]=sorted(rr)
 old=json.loads((ROOT/'daemon_header_codec_source.json').read_text());preserve=[]
 for n in ['word','after_identifier','tag','after_tag','word_call','after_extent']:
  assert not{p+str(r)for r in KEYREGS for p in('x','w')}&set(old['register_write_sets'][n]);preserve.append({'file':'daemon_header_codec_source.json','fragment':n,'registers':sorted(KEYREGS),'written_registers':old['register_write_sets'][n]})
 for n in ['after_header','span_class','u64_class','u64_length','u64_call']:
  assert not{p+str(r)for r in KEYREGS|{20}for p in('x','w')}&set(writes[n])
 live=[]
 for name,a,z,regs in [('word',0x100546fb0,0x1005472bc,[20]),('u64_writer',0x1005a2c64,0x1005a37d0,[0]),('u64_writer',0x1005a2c5c,0x1005a37c4,[16]),('u64_writer',0x1005a2c34,0x1005a37d0,[14]),('u64_writer',0x1005a2c68,0x1005a2e38,[1]),('u64_writer',0x1005a2e54,0x1005a2f18,[17]),('u64_writer',0x1005a2f34,0x1005a3084,[17]),('u64_writer',0x1005a30a0,0x1005a3214,[2])]:
  rr=set()
  for i in dc.disasm(IMAGE.read(a,z-a),a):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  assert not{p+str(r)for r in regs for p in('x','w')}&rr;live.append({'fragment':name,'start':hex(a),'end':hex(z),'preserved_registers':regs,'written_registers':sorted(rr)})
 groups=constants(fs)
 for cg in groups:
  if cg['fragment']!='key_setup':continue
  rr=set();a=int(cg['end'],16);z=int(fs['key_setup']['end'],16)
  for i in dc.disasm(IMAGE.read(a,z-a),a):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  assert not{p+str(cg['register'])for p in('x','w')}&rr;live.append({'fragment':'key_setup','start':hex(a),'end':hex(z),'preserved_registers':[cg['register']],'written_registers':sorted(rr)})
 assert not{'x20','w20'}&set(old['register_write_sets']['after_extent'])
 states=known_states(fs,groups);ptr=[]
 for ix in INDICES:
  a=TABLE+8*ix;ptr.append({'index':hex(ix),'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]})
 rec=[]
 for fn in ['daemon_constructor_inputs_source.json','daemon_header_codec_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'file':fn,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 pp=[];countnames=['after_header','u32_class','u32_length','u32_call','span_class','span_tag','u64_class','u64_length','u64_call','u64_writer','failure_gate','failure_entry']
 for p in json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles']:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed'];ev=[e for e in p['pac_bypasses']if e.get('target')in[hex(BLOCKS[n])for n in countnames]];counts={n:sum(e.get('target')==hex(BLOCKS[n])for e in ev)for n in countnames}
  assert counts==dict(zip(countnames,[5,3,3,3,2,2,0,0,0,0,0,0]));assert all(e['authentication']=='bypassed in private synthetic model'for e in ev);pp.append({'label':p['label'],'counts':counts,'events':ev,'native_evidence':False})
 assert len(pp)==12
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in ptr:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 deps=['daemon_constructor_inputs_source.json','daemon_constructor_inputs_checks.json','daemon_constructor_lookup_checks.json','daemon_header_codec_source.json','daemon_header_codec_checks.json','arcade_subscription_profiles.json','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt']
 return{'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'register_write_sets':writes,'constant_groups':groups,'liveness_intervals':live,'constant_states_before_writer_sites':states,'prior_key_preservation':preserve,'pointer_records':ptr,'prior_recaptures':rec,'retained_profiles':pp,'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},'verified_source_counts':{'fragments':len(fs),'instructions':sum(len(f['instructions'])for f in fs.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'constant_groups':len(groups),'liveness_intervals':len(live),'pointer_records':len(ptr),'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec),'retained_profiles':len(pp),'u32_routes':36,'span_routes':24,'u64_routes_observed':0},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
