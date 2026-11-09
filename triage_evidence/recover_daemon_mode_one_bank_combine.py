#!/usr/bin/env python3
"""Original two-bank combiner and its initializer/source-register lineage."""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_bank_combine'
SCOPE='Selected protected-core two-bank combination:universal u32 circuit/addition identities,compact bank outputs and private control. No whole operation,caller output,native PAC or daemon-kext exchange proof.'
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;fs={};writes={};slots=set();edges=[];rec=[]
 for n,a in [('combine',0x100bdba34),('initializer',0x100dda7d8)]:
  f=block(a,0x3000);bb=bytes.fromhex(f['bytes']);f['sha256']=h(bb);fs[n]=f;rr=set()
  for i in dc.disasm(bb,a):rr.update(i.reg_name(r)for r in i.regs_access()[1])
  assert 'sp'not in rr and f['instructions'][-1]['mnemonic']=='braa';writes[n]=sorted(rr)
 for n,ix,target in [('initializer',0x6284,0x100bdba34),('combine',0x4cf9,0x100dab3d0)]:
  f=fs[n];mod=int(f['instructions'][-2]['operands'].split('#')[1],0);slot=TABLE+ix*8;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63 and(word>>32)&65535==mod and not(word>>48&7)and FIXUPS[slot]['target']==target;slots.add(slot)
  edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 old=json.loads(read(ROOT/'daemon_mode_one_post_table_passes_source.json'))
 for n,f in old['fragments'].items():
  bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'fragment':n,'bytes_checked':len(bb),'sha256':h(bb)})
 assert fs['initializer']['instructions']==old['fragments']['initializer']['instructions']
 assert[(i['mnemonic'],i['operands'])for i in fs['combine']['instructions']if i['mnemonic'].startswith('str')]==[('str','w0, [sp, #0x448]')]
 counts={'source_ranges':2,'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'new_instructions':len(fs['combine']['instructions']),'pointer_records':2,'branch_slot_modifier_matches':2,'SP_writes':0,'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(r['bytes_checked']for r in rec)}
 return {'generator_sha256':sha(__file__),'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'static_scope':SCOPE,'fragments':fs,'branch_edges':edges,'original_pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'prior_recaptures':rec,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in['daemon_mode_one_post_table_passes_source.json','daemon_mode_one_post_table_passes_checks.json','daemon_mode_one_digit_maps_checks.json','daemon_receive_fixups.txt']},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
