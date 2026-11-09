#!/usr/bin/env python3
"""Recapture selected-record byte passes and common scratch initialization."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_record_passes'
SCOPE='Conditional selected-record processing:two ordered COUNT-byte passes,exact unsigned loop controls and modulo257 reduction,retained accumulator banks,common16-cell scratch initialization and saved-state epochs. Source/ABI results only;native owners,whole reachability,algorithm identity,successful output,budget history and daemon-kext pairing remain unknown.'
BLOCKS={'first_seed':0x100d863f4,'first':0x100d8ac5c,'repeat':0x100bf6c40,'between':0x100d03b1c,'second':0x100dacfa8,'restore':0x100b088f0,'scatter_seed':0x100bf2aa0,'scatter':0x100c91948}
EDGES={'first_seed':[(0x1f20,0x100d8ac5c)],'first':[(0xa927,0x100bf6c40),(0xa91b,0x100d03b1c)],'repeat':[(0x1f20,0x100d8ac5c)],'between':[(0x5d1a,0x100dacfa8)],'second':[(0x6ee2,0x100dacfa8),(0x6ed7,0x100b088f0)],'restore':[(0x324a,0x100bf2aa0)],'scatter_seed':[(0x2f1e,0x100c91948)],'scatter':[(0x2f1e,0x100c91948),(0x2f3b,0x100dcfa10)]}
DEPS=['daemon_mode_one_record_scan_source.json','daemon_mode_one_record_scan_checks.json','daemon_mode_one_phase_handoff_source.json','daemon_mode_one_phase_handoff_checks.json','daemon_receive_fixups.txt']
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;fs={n:block(a,0x10000)for n,a in BLOCKS.items()}
 writes={};corrections=[]
 for n,f in fs.items():
  raw=bytes.fromhex(f['bytes']);f['sha256']=h(raw);rr=set();assert len(raw)==4*len(f['instructions'])
  for i in dc.disasm(raw,int(f['start'],16)):
   ww={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f;bad={r for r in ww if re.fullmatch('[xw][0-9]+',r)}
    if bad:corrections.append({'site':hex(i.address),'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    ww-=bad
   rr.update(ww)
  assert 'sp'not in rr;writes[n]=sorted(rr);controls=[i['mnemonic']for i in f['instructions']if i['mnemonic']in ['b','br','bl','blr','braa','brab','blraa','blrab','svc','ret','retab']or i['mnemonic'].startswith(('b.','cb','tb'))];assert controls==(['braa']if n in BLOCKS else [])
 edges=[];slots=set()
 for n,rows in EDGES.items():
  mod=int(fs[n]['instructions'][-2]['operands'].split('#')[1],0)
  for ix,target in rows:
   slot=TABLE+8*ix;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==mod and not(word>>48&7)and FIXUPS[slot]['target']==target;slots.add(slot);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 rec=[]
 for name in [DEPS[0],DEPS[2]]:
  for label,f in json.loads(read(ROOT/name))['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'artifact':name,'fragment':label,'bytes_checked':len(raw),'sha256':h(raw)})
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_bindings':len(edges),'SP_writes':0,'comparison_role_corrections':len(corrections),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(v['bytes_checked']for v in rec)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'fragments':fs,'branch_edges':edges,'pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'comparison_role_corrections':corrections,'prior_recaptures':rec,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in DEPS},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
