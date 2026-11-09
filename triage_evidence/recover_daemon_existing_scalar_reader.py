#!/usr/bin/env python3
"""Original-source existing-record u32 reader; frozen evidence only."""
import json,re,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,sha,h,FLAGS
from daemon_receive_tools import verify_original_fixups
P='daemon_existing_scalar_reader'
SCOPE='Conditional existing-record header/type/extent/u32 output contract and source codecs; no new target execution, native owner/PAC/peer proof or whole interface completion.'
BLOCKS={'header_return':0x10051e2c0,'tag':0x1005122cc,'tag_return':0x1004e2ee8,'word_call':0x100530d34,'length_guard':0x10052b3e8,'invalid':0x1008eb300,'split':0x10052af04,'split_high':0x10058ead4,'u64_check':0x1004d6a78,'span_check':0x1005137e4,'u32_check':0x1004d1fe4,'type_mismatch':0x100555178,'u32_extent':0x10057a734,'payload_call':0x1005be67c,'payload_return':0x100530108,'publish':0x100506a0c,'return':0x1006f76a8,'prepare':0x1006f6bf0,'word':0x100800004}
EDGES={'header_return':[0x1f39],'tag':[0x212],'tag_return':[0x3a31],'word_call':[0x8c3f],'length_guard':[0xb4bf,0xb4dd],'invalid':[0x2a7b],'split':[0x9a1c,0x9a43],'split_high':[0x698a,0x6999],'u64_check':[0x642b,0x643c],'span_check':[0x642b,0x643c],'u32_check':[0x643c,0x9fe7],'type_mismatch':[0x3cc0],'u32_extent':[0xb4bf,0xb81e],'payload_call':[0x3a31],'payload_return':[0x3cc0,0x68cb],'publish':[0x3cc0],'prepare':[0x8c3f],'word':[0x74,0xef,0xb3]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f
 edges=[];indices={0x922}
 for n,ixs in EDGES.items():
  ii=fs[n]['instructions'];mod=int(ii[-2]['operands'].split('#')[1],0);rows=[]
  for ix in ixs:
   a=TABLE+8*ix;w=int.from_bytes(IMAGE.read(a,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix));rows.append({'index':hex(ix),'slot':hex(a),'target':hex(FIXUPS[a]['target'])});indices.add(ix)
  edges.append({'fragment':n,'branch_site':ii[-1]['ea'],'modifier_u16':mod,'slots':rows})
 pointers=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)]
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;registers={};controls={}
 for n,f in fs.items():
  ii=list(dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)));registers[n]=sorted({i.reg_name(r)for i in ii for r in i.regs_access()[1]});controls[n]=[{'ea':hex(i.address),'mnemonic':i.mnemonic}for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','retaa','svc','hvc','smc')];assert len(controls[n])==1 and controls[n][0]['mnemonic']=='braa'
 for n in ['tag','word']:assert not any(i['mnemonic'].startswith('st')for i in fs[n]['instructions'])
 assert not {'x1','w1','x4','w4','x16','w16'}&set(registers['prepare'])
 liveness=[]
 for names,regs in [(['header_return','tag','tag_return','word_call','length_guard','split','split_high','u32_check','u32_extent','payload_call','word'],[9,19,20,21,23,25,26,27]),(['header_return','tag','length_guard'],[28]),(['split','split_high','u64_check','span_check'],[16]),(['word_call','split_high','u32_check','u32_extent','payload_call'],[6])]:
  for n in names:
   assert not {p+str(r)for r in regs for p in ('w','x')}&set(registers[n]),(n,regs)
   liveness.append({'fragment':n,'preserved_register_numbers':regs,'written_registers':registers[n]})
 old=json.loads((ROOT/'daemon_scalar_field_population_source.json').read_text());lookup=json.loads((ROOT/'daemon_constructor_lookup_source.json').read_text());rec=[]
 for fn,obj in [('daemon_scalar_field_population_source.json',old),('daemon_constructor_lookup_source.json',lookup)]:
  for n,f in obj['fragments'].items():
   b=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(b))==b;rec.append({'file':fn,'fragment':n,'bytes_checked':len(b),'sha256':h(b)})
 profiles=[]
 for p in old['retained_profiles']:
  assert p['episode']['counts']['found_node']==0
  profiles.append({'label':p['label'],'found_value_entries_observed':0,'wire_field':p['wire_field'],'scope':'Existing packet bytes only; this getter is not entered in the retained episode and is not replayed here.'})
 assert len(profiles)==12
 command=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(command,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in pointers:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 deps=['daemon_scalar_field_population_source.json','daemon_scalar_field_population_checks.json','daemon_constructor_lookup_source.json','daemon_constructor_lookup_checks.json','daemon_header_codec_source.json','daemon_header_codec_checks.json','daemon_payload_codec_source.json','daemon_payload_codec_checks.json','arcade_subscription_profiles.json','daemon_receive_fixups.txt']
 counts={'source_fragments':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(pointers),'branch_slot_modifier_matches':sum(len(e['slots'])for e in edges),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec),'frozen_profiles':len(profiles),'found_value_entries_observed':0}
 counts['register_liveness_checks']=len(liveness)
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'pointer_records':pointers,'original_fixup_checks':verify_original_fixups({int(r['slot'],16)for r in pointers}),'register_write_sets':registers,'liveness_intervals':liveness,'control_ledger':controls,'prior_recaptures':rec,'retained_profiles':profiles,'fixup_reference':{'command':command,'tool_sha256':sha(command[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
