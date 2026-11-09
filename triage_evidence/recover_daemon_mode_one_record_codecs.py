#!/usr/bin/env python3
"""Recapture the selected-record XOR/codebook writers and their phase gate."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_record_codecs'
SCOPE='Conditional selected-record XOR table,input decoder,output encoder and count gate;source-linked static contracts under distinct P/Q codebooks. Native reachability,owners,P=Q,successful publication,complete budget history and daemon-kext pairing remain unknown.'
BLOCKS={'xor':0x100d5e270,'decode':0x100d9e050,'encode':0x100d03c9c,'gate':0x100d69d98}
EDGES={'xor':[(0x853e,0x100d5e270),(0x84e8,0x100d9e050)],'decode':[(0x84e8,0x100d9e050),(0xb43f,0x100d03c9c)],'encode':[(0xa102,0x100d03c9c),(0xa0fd,0x100d69d98)],'gate':[(0x8284,0x100ca1ef8),(0x828b,0x100c7d5dc)]}
DEPS=['daemon_mode_one_record_adder_source.json','daemon_mode_one_record_adder_checks.json','daemon_mode_one_record_permutation_source.json','daemon_mode_one_record_permutation_checks.json','daemon_receive_fixups.txt']
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 fs={n:block(a,0x4000)for n,a in BLOCKS.items()};writes={};corrections=[]
 for n,f in fs.items():
  raw=bytes.fromhex(f['bytes']);assert len(raw)==4*len(f['instructions']);f['sha256']=h(raw);rr=set()
  for i in dc.disasm(raw,int(f['start'],16)):
   ww={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f
    bad={r for r in ww if re.fullmatch('[xw][0-9]+',r)}
    if bad:corrections.append({'site':hex(i.address),'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    ww-=bad
   rr.update(ww)
  assert 'sp'not in rr;writes[n]=sorted(rr)
  controls=[i['mnemonic']for i in f['instructions']if i['mnemonic']in ['b','br','bl','blr','braa','brab','blraa','blrab','svc','ret','retab']or i['mnemonic'].startswith(('b.','cb','tb'))]
  assert controls==['braa']
 edges=[];slots=set()
 for n,rows in EDGES.items():
  mod=int(fs[n]['instructions'][-2]['operands'].split('#')[1],0)
  for ix,target in rows:
   slot=TABLE+8*ix;word=int.from_bytes(IMAGE.read(slot,8),'little')
   assert word>>63 and(word>>32)&65535==mod and not(word>>48&7)and FIXUPS[slot]['target']==target
   slots.add(slot);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 parent=json.loads(read(ROOT/DEPS[0]));data=next(v for v in parent['data_roots']if v['role']=='operation');slot=int(data['slot'],16)
 assert data['fixup']==FIXUPS[slot]and IMAGE.read(slot,8).hex()==data['raw_bytes']and(FIXUPS[slot]['target']+int(data['bias_u64'],16))%2**64==0x100f4a640
 assert IMAGE.read(0x100f4a640,928).hex()==data['bytes']and h(bytes.fromhex(data['bytes']))==data['sha256'];slots.add(slot)
 rec=[]
 for name in [DEPS[0],DEPS[2]]:
  for label,f in json.loads(read(ROOT/name))['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw
   rec.append({'artifact':name,'fragment':label,'start':f['start'],'bytes_checked':len(raw),'sha256':h(raw)})
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_bindings':len(edges),'data_ranges':1,'data_bytes':928,'SP_writes':0,'comparison_role_corrections':len(corrections),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(v['bytes_checked']for v in rec)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'branch_edges':edges,'operation_image':data,'pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'comparison_role_corrections':corrections,'prior_recaptures':rec,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in DEPS},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
