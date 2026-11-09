#!/usr/bin/env python3
"""Read-only header/word-writer source and frozen write-ledger extraction."""
import json,re,subprocess,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,CS,TABLE,block,sha,h,FLAGS
P='daemon_header_codec'
SCOPE='Conditional encoded BE32 writer, two-byte discriminator writer, three header-field call contracts and u32 scalar-payload call contract; compositional common address-mask proof and retained private store-PC/offset evidence. Native phase, ownership, admission, PAC and endpoint joins remain unproved.'
BLOCKS={'prepare':0x1008314ec,'key_setup':0x1008ecb78,'word':0x100546c90,'after_identifier':0x100617400,
 'tag':0x1007b28a4,'after_tag':0x1005979d4,'word_call':0x100615004,'after_extent':0x10047cd38,
 'constructor_return':0x1004f4bc4,'scalar_call':0x100534f24,'node_alloc':0x1006958b0,'record_alloc':0x100948a8c}
WORD_PCS=['0x100546e54','0x100546fe8','0x1005471b4','0x1005472a8'];TAG_PCS=['0x1007b29f0','0x1007b2b50']
CONSTANT_REGS={0,1,4,5,8,9,10,11,12,13,14,15,19,23,26,27,28,30}
def profiles():
 rows=[]
 for p in json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles']:
  if p['stop_reason']!='outgoing_arcade_xpc_message_boundary':continue
  assert p['source_sha256']==sha(SOURCE)and not p['native_target_executed']and not p['target_host_operations_executed']
  bufs=[c for c in p['calls']if c['return_pc']=='0x100948bfc'];assert len(bufs)==5;records=[]
  for c in bufs:
   ptr=c['result'];n=int(c['args'][0],16)
   ww=[{'record_index':j,**r}for j,r in enumerate(p['records'])if r['kind']=='native_heap_write'and r['allocation']==ptr]
   header=[w for w in ww if w['offset_bytes']<10];expected=list(zip(WORD_PCS,range(4)))+list(zip(TAG_PCS,[4,5]))+list(zip(WORD_PCS,range(6,10)))
   assert[(w['pc'],w['offset_bytes'])for w in header]==expected and all(w['size_bytes']==1 for w in header)
   scalar=[w for w in ww if w['pc']in WORD_PCS and w['offset_bytes']>=10]
   if n==14:assert[(w['pc'],w['offset_bytes'])for w in scalar]==list(zip(WORD_PCS,range(10,14)))
   else:assert not scalar
   records.append({'buffer':ptr,'allocation_extent_bytes':n,'header_stores':header,'scalar_word_stores':scalar})
  events=p['pac_bypasses'];entries=[e for e in events if e.get('target')=='0x100546c90'];tags=[e for e in events if e.get('target')=='0x1007b28a4']
  assert len(entries)==13 and len(tags)==5 and sum(e['site']=='0x1008ece18'for e in entries)==5 and sum(e['site']=='0x100615018'for e in entries)==8
  assert all(e['authentication']=='bypassed in private synthetic model'for e in entries+tags)
  rows.append({'label':p['label'],'records':records,'word_entry_events':entries,'tag_entry_events':tags,'native_evidence':False})
 assert len(rows)==12;return rows
def build():
 fs={}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f
 constants=[];ii=fs['key_setup']['instructions']
 for j,i in enumerate(ii):
  if i['mnemonic']=='mov'and i['operands'].startswith('x')and ', #'in i['operands']:
   group=ii[j:j+4]
   if len(group)==4 and all(q['mnemonic']=='movk'and q['operands'].split(',')[0]==i['operands'].split(',')[0]for q in group[1:]):constants.append({'register':i['operands'].split(',')[0],'start':i['ea'],'end':hex(int(group[-1]['ea'],16)+4),'instructions':group})
 assert {int(c['register'][1:])for c in constants}==CONSTANT_REGS
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;writes={}
 for n,f in fs.items():
  rr=set()
  for i in dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  writes[n]=sorted(rr)
 assert not {'w22','x22','w16','x16','w24','x24'}&set(writes['key_setup'])
 assert not {'w19','x19','w21','x21'}&set(writes['node_alloc'])and not {'w19','x19'}&set(writes['record_alloc'])
 rec=[]
 for fn in ['daemon_payload_codec_source.json']:
  for n,f in json.loads((ROOT/fn).read_text())['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'file':fn,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 targets={BLOCKS[n]for n in ['key_setup','word','after_identifier','tag','after_tag','word_call','after_extent','constructor_return']}|{0x1005ae7a0};ptrs=[]
 for at,r in sorted(FIXUPS.items()):
  if r['target']in targets:ptrs.append({'slot':hex(at),'index':hex((at-TABLE)//8),'raw_bytes':IMAGE.read(at,8).hex(),'fixup':r})
 cmd=['/usr/bin/dyld_info','-fixups',str(SOURCE)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr;fresh={}
 for line in r.stdout.splitlines():
  m=re.match(r'\s+\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)(.*)',line)
  if m:fresh[int(m[1],16)]=line.strip()
 assert set(fresh)==set(FIXUPS)
 for row in ptrs:assert fresh[int(row['slot'],16)]==row['fixup']['line']
 pp=profiles();deps=['daemon_payload_codec_source.json','daemon_payload_codec_checks.json','recover_daemon_payload_codec.py','validate_daemon_payload_codec.py','validate_daemon_list_output.py','arcade_subscription_profiles.json','recover_daemon_xpc_core_bridge.py','daemon_receive_fixups.txt']
 return{'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},
  'fragments':fs,'constant_groups':constants,'register_write_sets':writes,'pointer_records':ptrs,'prior_recaptures':rec,'retained_profiles':pp,
  'fixup_reference':{'command':cmd,'tool_sha256':sha(cmd[0]),'stdout_sha256':h(r.stdout.encode()),'catalog_memberships_compared':len(fresh)},
  'verified_source_counts':{'fragments':len(fs),'instructions':sum(len(f['instructions'])for f in fs.values()),'fragment_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'constant_groups':len(constants),'pointer_records':len(ptrs),'prior_ranges':len(rec),'prior_bytes':sum(r['bytes_checked']for r in rec),'retained_profiles':12,'constructed_headers':60,'header_byte_stores':600,'scalar_payload_byte_stores':144,'word_entry_events':156,'tag_entry_events':60},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
