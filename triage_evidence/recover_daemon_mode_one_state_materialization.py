#!/usr/bin/env python3
"""Original register spills,128-byte state materializer and entry lineage."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_state_materialization'
SCOPE='Selected mode1 register-to-frame and128-byte scattered-state materialization. Static source and layout/control proofs only;compact whole expansion,caller output,native PAC and daemon-kext exchange remain unknown.'
ENTRIES={'spills':0x100bf3160,'bytes':0x100c9d2b8,'initializer':0x100dda7d8}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;fs={};writes={};corrections=[];edges=[];slots=set();rec=[]
 for n,a in ENTRIES.items():fs[n]=block(a,0x4000)
 a,b=0x100dab3e8,0x100dab3f0;bb=IMAGE.read(a,b-a);fs['phase_seed']={'start':hex(a),'end':hex(b),'bytes':bb.hex(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in dc.disasm(bb,a)]}
 for n,f in fs.items():
  bb=bytes.fromhex(f['bytes']);f['sha256']=h(bb);ww=set()
  for i in dc.disasm(bb,int(f['start'],16)):
   rr={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f;bad={r for r in rr if re.fullmatch('[xw][0-9]+',r)}
    if bad:corrections.append({'site':hex(i.address),'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    rr-=bad
   ww.update(rr)
  assert 'sp'not in ww;writes[n]=sorted(ww)
 for n,ix,target in [('spills',0x3146,0x100c9d2b8),('bytes',0xbce7,0x100a763d4),('bytes',0xbcff,0x100c21d7c)]:
  f=fs[n];mod=int(f['instructions'][-2]['operands'].split('#')[1],0);slot=TABLE+8*ix;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==mod and not(word>>48&7)and FIXUPS[slot]['target']==target;slots.add(slot)
  edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 for name in['daemon_mode_one_word_mix_source.json','daemon_mode_one_bank_combine_source.json','daemon_mode_one_post_table_passes_source.json','daemon_mode_one_digit_maps_source.json']:
  old=json.loads(read(ROOT/name))
  for n,f in old['fragments'].items():
   bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'artifact':name,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 # The context and byte-encoding constants survive the two intervening blocks.
 for name,fragment in [('daemon_mode_one_bank_combine_source.json','combine'),('daemon_mode_one_word_mix_source.json','mix')]:
  old=json.loads(read(ROOT/name))['fragments'][fragment]
  assert not any(i['mnemonic']not in['cmp','str','strb','braa']and i['operands'].split(',')[0]in['w24','x24','w27','x27','w28','x28']for i in old['instructions'])
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'new_instructions':len(fs['spills']['instructions'])+len(fs['bytes']['instructions']),'pointer_records':3,'branch_slot_modifier_matches':3,'SP_writes':0,'comparison_operand_role_corrections':len(corrections),'new_byte_store_sites':sum(i['mnemonic']=='strb'for i in fs['bytes']['instructions']),'new_word_store_sites':sum(i['mnemonic']=='str'for n in['spills','bytes']for i in fs[n]['instructions']),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec)}
 return {'generator_sha256':sha(__file__),'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'static_scope':SCOPE,'fragments':fs,'branch_edges':edges,'original_pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'comparison_role_corrections':corrections,'prior_recaptures':rec,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in['daemon_mode_one_word_mix_source.json','daemon_mode_one_word_mix_checks.json','daemon_mode_one_post_table_passes_checks.json','daemon_mode_one_digit_maps_checks.json','daemon_receive_fixups.txt']},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
