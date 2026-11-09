#!/usr/bin/env python3
"""Original two32-byte passes and state handoff;no target execution or IDB effects."""
import json,capstone,re
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_mode_one_source_passes'
SCOPE='Selected nonnull LEN32 protected-core branch:two ordered32-byte source passes,four-word state banks,shared compact recurrence and conditionally equal final banks and exact reduction257,state preservation and second-bank spill/handoff. Algorithm identity,later consumers/output,budget/return,native owners/PAC and daemon-kext exchange remain unproved.'
BLOCKS={'entry':0x100d5dfc8,'seed':0x100d77734,'first':0x100b035ac,'between':0x100d64e2c,'second':0x100d9f0f4,'handoff':0x100d5e37c}
EDGES={'entry':[0xbce2,0xbcf3],'seed':[0x2e5e],'first':[0xbd2a,0xbd5a],'between':[0x303e],'second':[0x303e,0x306c],'handoff':[0x3d26]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';fs={};edges=[];slots=set();writes={};corrections=[];dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in BLOCKS.items():
  f=block(a,0x3000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f;mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES[n]:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix),hex(mod),hex(w));slots.add(slot);edges.append({'fragment':n,'index':hex(ix),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
  rr=set();ii=list(dc.disasm(bytes.fromhex(f['bytes']),a))
  for i in ii:
   written={i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic=='cmp':
    word=int.from_bytes(i.bytes,'little');assert word&0x6000001f==0x6000001f
    removed={r for r in written if re.fullmatch('[xw][0-9]+',r)}
    if removed:corrections.append({'site':hex(i.address),'bytes':i.bytes.hex(),'operands':i.op_str,'reported_GPR_writes':sorted(removed),'architectural_GPR_writes':[],'basis':'CMP alias of SUBS to zero register,Rd31,S1,sub1;compared GPRs are read operands'})
    written-=removed
   rr.update(written)
  writes[n]=sorted(rr);assert 'sp'not in rr;assert [i.mnemonic for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','svc','hvc','smc')]==['braa']
 assert not any(q.startswith('str')for f in ['first','second']for q in [i['mnemonic']for i in fs[f]['instructions']]);assert not {'x0','w0','x1','w1','x2','w2','x3','w3','x30','w30'}&set(writes['between']+writes['second']+writes['handoff'])
 invariants={'first':[4,5,6,7,8,9,10,11,12,16,21,22,23,24,25,26,27,28,30],'second':[0,1,2,3,4,5,6,7,9,12,14,16,19,20,21,24,25,27,28,30]}
 for n,regs in invariants.items():assert not{int(r[1:])for r in writes[n]if re.fullmatch('[xw][0-9]+',r)}&set(regs)
 stores=[]
 for n,f in fs.items():
  for i in f['instructions']:
   if i['mnemonic'].startswith('st'):
    assert i['mnemonic']=='str';m=re.fullmatch(r'([xw]\d+), \[sp, #(0x[0-9a-f]+)\]',i['operands']);assert m,i;stores.append({'fragment':n,'site':i['ea'],'frame_offset':int(m[2],16),'width_bytes':4 if m[1].startswith('w')else 8})
 assert len(stores)==12 and sum(q['width_bytes']for q in stores)==72
 old=json.loads(read(ROOT/'daemon_mode_one_adapter_source.json'));rec=[]
 for n,f in old['fragments'].items():
  bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;rec.append({'file':'daemon_mode_one_adapter_source.json','fragment':n,'start':f['start'],'bytes_checked':len(bb),'sha256':h(bb)})
 ptr=[{'slot':hex(a),'raw_bytes':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}for a in sorted(slots)]
 deps=['daemon_mode_one_adapter_source.json','daemon_mode_one_adapter_checks.json','validate_daemon_reader_outer_lifecycle.py','validate_daemon_existing_scalar_reader.py','validate_daemon_reader_container_origins.py','daemon_receive_fixups.txt']
 counts={'source_ranges':len(fs),'source_instructions':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(q['bytes_checked']for q in rec),'source_SP_writes':0,'comparison_operand_role_corrections':len(corrections),'loop_store_instructions':0,'source_store_sites':len(stores),'source_store_bytes':sum(q['width_bytes']for q in stores),'distinct_frame_store_bytes':len({q['frame_offset']+j for q in stores for j in range(q['width_bytes'])})}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'register_write_sets':writes,'frame_store_ledger':stores,'loop_invariant_registers':invariants,'comparison_role_corrections':corrections,'Capstone_version':capstone.__version__,'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups(slots),'prior_recaptures':rec,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
