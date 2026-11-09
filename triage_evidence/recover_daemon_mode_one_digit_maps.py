#!/usr/bin/env python3
"""Original XOR-table and digit-label map producers;static extraction only."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_digit_maps'
SCOPE='Selected mode1 encoded XOR table and forward/inverse natural-digit maps. Source and finite algebra only;whole operation,caller output,native PAC and daemon-kext exchange remain unknown.'
ENTRIES={'xor':0x100c9589c,'decoder':0x100c6ff08,'relabel':0x100d17960,'carry_seed':0x100c18e20}
EDGE_SPECS=[('xor',0xa648,0x100c9589c),('xor',0xa659,0x100c6ff08),('decoder',0xa659,0x100c6ff08),('decoder',0xb395,0x100d17960),('relabel',0x4e26,0x100d17960),('relabel',0x4def,0x100daee68)]
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 old=json.loads(read(ROOT/'daemon_mode_one_carry_table_source.json'));op=old['operation_data'];dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 fs={};writes={};corrections=[];edges=[];slots={int(op['slot'],16)}
 for name,a in ENTRIES.items():
  f=block(a,0x2000);bb=bytes.fromhex(f['bytes']);f['sha256']=h(bb);fs[name]=f;ww=set();assert f['instructions'][-1]['mnemonic']=='braa'
  for i in dc.disasm(bb,a):
   rr={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f;bad={r for r in rr if re.fullmatch('[xw][0-9]+',r)}
    if bad:corrections.append({'site':hex(i.address),'reported_GPR_writes':sorted(bad),'architectural_GPR_writes':[]})
    rr-=bad
   ww.update(rr)
  assert 'sp'not in ww;writes[name]=sorted(ww)
 for name,index,target in EDGE_SPECS:
  f=fs[name];mod=int(f['instructions'][-2]['operands'].split('#')[1],0);slot=TABLE+index*8;word=int.from_bytes(IMAGE.read(slot,8),'little')
  assert word>>63 and(word>>32)&65535==mod and not(word>>48&7)and FIXUPS[slot]['target']==target;slots.add(slot)
  edges.append({'fragment':name,'index':hex(index),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(mod),'raw_bytes':IMAGE.read(slot,8).hex(),'fixup':FIXUPS[slot]})
 for f in old['fragments'].values():assert IMAGE.read(int(f['start'],16),len(bytes.fromhex(f['bytes'])))==bytes.fromhex(f['bytes'])
 assert IMAGE.read(int(op['target'],16),op['size_bytes'])==bytes.fromhex(op['bytes'])
 assert fs['carry_seed']['instructions']==old['fragments']['carry']['instructions']
 counts={'source_ranges':4,'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'new_routine_instructions':sum(len(fs[n]['instructions'])for n in['xor','decoder','relabel']),'new_routine_bytes':sum(len(bytes.fromhex(fs[n]['bytes']))for n in['xor','decoder','relabel']),'pointer_records':len(slots),'branch_slot_modifier_matches':len(edges),'data_bytes':944,'SP_writes':0,'comparison_operand_role_corrections':len(corrections),'prior_source_ranges_recaptured':len(old['fragments']),'prior_source_bytes_recaptured':sum(len(bytes.fromhex(f['bytes']))for f in old['fragments'].values())}
 return {'generator_sha256':sha(__file__),'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'static_scope':SCOPE,'fragments':fs,'branch_edges':edges,'operation_data':op,'pointer_checks':verify_original_fixups(slots),'register_write_sets':writes,'comparison_role_corrections':corrections,'Capstone_version':capstone.__version__,'dependencies':{n:sha(ROOT/n)for n in['daemon_mode_one_carry_table_source.json','daemon_mode_one_carry_table_checks.json','recover_daemon_mode_one_carry_table.py','validate_daemon_mode_one_carry_table.py','daemon_receive_fixups.txt']},'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
