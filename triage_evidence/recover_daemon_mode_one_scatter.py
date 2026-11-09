#!/usr/bin/env python3
"""Original-byte scatter/permutation extraction; read-only target access."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_scatter'
SCOPE='Selected LEN32 mode1 core continuation:16-byte scattered initialization and 15 state-dependent in-place swaps of those initialized cells. This is a static permutation contract; algorithm identity, downstream uses, complete return/budget history and native daemon-kext exchange remain unknown.'
BLOCKS={'handoff':0x100d5e37c,'scatter':0x100d4fde0,'permutation':0x100ca047c}
EDGES={'handoff':[0x3d26],'scatter':[0x3d26,0xc7ec],'permutation':[0x8a66]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={};edges=[];slots=set();writes={};corrections=[];dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in BLOCKS.items():
  f=block(a,0x3000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f;mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES[n]:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7);slots.add(slot);edges.append({'fragment':n,'index':hex(ix),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
  rr=set()
  for i in dc.disasm(bytes.fromhex(f['bytes']),a):
   ww={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic in('cmp','tst'):
    word=int.from_bytes(i.bytes,'little');assert word&31==31 and word&(1<<29)
    if i.mnemonic=='cmp':assert word&0x6000001f==0x6000001f
    removed={r for r in ww if re.fullmatch('[xw][0-9]+',r)}
    if removed:corrections.append({'site':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'reported_GPR_writes':sorted(removed),'architectural_GPR_writes':[]})
    ww-=removed
   rr.update(ww)
  writes[n]=sorted(rr);assert 'sp'not in rr
  assert [i['mnemonic']for i in f['instructions']if i['mnemonic']in('b','br','bl','blr','braa','brab','blraa','blrab','svc','hvc','smc','ret','retab')or i['mnemonic'].startswith(('b.','cb','tb'))]==['braa']
 assert not {'w0','x0','w1','x1','w2','x2','w3','x3'}&set(writes['handoff'])
 assert not {'w0','x0','w1','x1','w2','x2'}&set(writes['scatter'])
 assert [i['mnemonic']for i in fs['scatter']['instructions']if i['mnemonic'].startswith('st')]==['strb']
 assert len([i for i in fs['permutation']['instructions']if i['mnemonic']=='strb'])==30
 assert all(not i['mnemonic'].startswith('st')or i['mnemonic']=='strb'for i in fs['permutation']['instructions'])
 old=json.loads(read(ROOT/'daemon_mode_one_source_passes_source.json'));rec=[]
 for n,f in old['fragments'].items():
  bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'fragment':n,'start':f['start'],'bytes_checked':len(bb),'sha256':h(bb)})
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(slots),'branch_slot_modifier_matches':len(edges),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(q['bytes_checked']for q in rec),'SP_writes':0,'permutation_byte_store_sites':30,'comparison_operand_role_corrections':len(corrections)}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_artifact':'fairplayd.arm64e','daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['daemon_mode_one_source_passes_source.json','daemon_mode_one_source_passes_checks.json','validate_daemon_list_output.py','daemon_receive_fixups.txt']},'fragments':fs,'branch_edges':edges,'pointer_records':[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)],'original_fixup_checks':verify_original_fixups(slots),'register_write_sets':writes,'comparison_role_corrections':corrections,'Capstone_version':capstone.__version__,'prior_recaptures':rec,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
