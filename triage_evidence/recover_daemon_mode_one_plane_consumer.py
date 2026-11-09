#!/usr/bin/env python3
"""Original four-round scattered-plane consumer and private word-output roots."""
import json,capstone,re
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_plane_consumer'
SCOPE='Selected mode1 four-round consumer of both64-byte state planes,local scattered u32 stores,eight-word state handoff and exact biased-view/address reduction. Static only;compact full transform,caller publication and native daemon-kext exchange remain unknown.'
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={n:block(a,0x4000)for n,a in{'loop':0x100b4ef4c,'seed':0x100a763d4,'initializer':0x100dda7d8}.items()}
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;a,b=0x100d5dfd4,0x100d5dfe8;raw=IMAGE.read(a,b-a)
 fs['views']={'start':hex(a),'end':hex(b),'bytes':raw.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in dc.disasm(raw,a)]};edges=[];slots=set();writes={};corrections=[]
 for n,f in fs.items():
  raw=bytes.fromhex(f['bytes']);f['sha256']=h(raw);ww=set()
  for i in dc.disasm(raw,int(f['start'],16)):
   rr={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f;bad={r for r in rr if re.fullmatch('[xw][0-9]+',r)}
    if bad:corrections.append({'site':hex(i.address),'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    rr-=bad
   ww.update(rr)
  assert 'sp'not in ww;writes[n]=sorted(ww)
 for n,ix in[('seed',0x803e),('loop',0x803e),('loop',0x8049),('initializer',0x6284)]:
  mod=int(fs[n]['instructions'][-2]['operands'].split('#')[1],0);slot=TABLE+8*ix;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==mod and not(word>>48&7);slots.add(slot)
  edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 assert [r['target']for r in edges[:3]]==['0x100b4ef4c','0x100b4ef4c','0x100d76e6c']
 rec=[]
 for name in['daemon_mode_one_source_absorption_source.json','daemon_mode_one_source_passes_source.json']:
  old=json.loads(read(ROOT/name))
  for n,f in old['fragments'].items():
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'artifact':name,'fragment':n,'bytes_checked':len(raw),'sha256':h(raw)})
 return {'generator_sha256':sha(__file__),'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'static_scope':SCOPE,'fragments':fs,'branch_edges':edges,'original_pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'comparison_role_corrections':corrections,'prior_recaptures':rec,'dependencies':{n:sha(ROOT/n)for n in['daemon_mode_one_source_absorption_source.json','daemon_mode_one_source_absorption_checks.json','daemon_mode_one_source_passes_source.json','daemon_mode_one_digit_maps_checks.json','daemon_receive_fixups.txt']},'Capstone_version':capstone.__version__,'verified_source_counts':{'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_slot_modifier_matches':len(edges),'SP_writes':0,'comparison_operand_role_corrections':len(corrections),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec),'loop_byte_load_sites':sum(i['mnemonic']=='ldrb'for i in fs['loop']['instructions']),'loop_store_sites':sum(i['mnemonic']=='str'for i in fs['loop']['instructions'])},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
