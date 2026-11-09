#!/usr/bin/env python3
"""Original encoded-word mix,phase seed and size-word producer."""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_word_mix'
SCOPE='Selected protected-core word mix:five compact unary maps,size-word input,register contract and predecessor composition. Static only;whole operation,caller output,native PAC and daemon-kext exchange remain unknown.'
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;fs={'mix':block(0x100dab3d0,0x3000)};writes={};edges=[];slots=set();rec=[]
 for n,a,b in [('phase_seed',0x100bdbc58,0x100bdbcbc),('size_word',0x100dda7d8,0x100dda884)]:
  bb=IMAGE.read(a,b-a);ii=list(dc.disasm(bb,a));assert len(ii)*4==len(bb);fs[n]={'start':hex(a),'end':hex(b),'bytes':bb.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]}
 for n,f in fs.items():
  bb=bytes.fromhex(f['bytes']);f['sha256']=h(bb);ww=set()
  for i in dc.disasm(bb,int(f['start'],16)):ww.update(i.reg_name(r)for r in i.regs_access()[1])
  assert 'sp'not in ww;writes[n]=sorted(ww)
 for n,ix,target in [('phase_seed',0x4cf9,0x100dab3d0),('mix',0x17d8,0x100bf3160)]:
  f=fs[n];mod=int(f['instructions'][-2]['operands'].split('#')[1],0);slot=TABLE+8*ix;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==mod and not(word>>48&7)and FIXUPS[slot]['target']==target;slots.add(slot)
  edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 for name in['daemon_mode_one_bank_combine_source.json','daemon_mode_one_post_table_passes_source.json']:
  old=json.loads(read(ROOT/name))
  for n,f in old['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'artifact':name,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 assert not any(i['mnemonic'].startswith('str')for i in fs['mix']['instructions'])
 counts={'source_ranges':3,'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'new_instructions':len(fs['mix']['instructions']),'pointer_records':2,'branch_slot_modifier_matches':2,'SP_writes':0,'new_store_instructions':0,'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec)}
 return {'generator_sha256':sha(__file__),'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'static_scope':SCOPE,'fragments':fs,'branch_edges':edges,'original_pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'prior_recaptures':rec,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in['daemon_mode_one_bank_combine_source.json','daemon_mode_one_bank_combine_checks.json','daemon_mode_one_post_table_passes_source.json','daemon_mode_one_post_table_passes_checks.json','daemon_receive_fixups.txt']},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
