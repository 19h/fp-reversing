#!/usr/bin/env python3
"""Original-source nested-record lookup, span admission and N19 input lineage."""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,block,h,FLAGS
from recover_daemon_context_input_producers import scan
from daemon_receive_tools import verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha,read
P='daemon_reader_nested_input'
SCOPE='Selected outer context-word discriminator, first-child key7615e796 lookup, matched-record buffer/header/extent/type interfaces, borrowed span BUF+10 and encoded length into N19, and conditional default-context admission. No continuous native caller, owner/PAC, complete non-span accessor, external delivery or daemon-kext pairing proof.'
BLOCKS={'mode':0x1006bf434,'head':0x1006ab91c,'lookup_call':0x1006d6c00,'lookup_entry':0x1006fd1b8,'lookup_return':0x1006d913c,'buffer':0x1006d038c,'minimum':0x1008caee0,'word_prepare':0x1008a9d38,'word_return':0x10059ad28,'tag_return':0x100609f40,'word_call':0x100530d34,'extent':0x1006ec8f8,'fit':0x1007cfed8,'type':0x100798550,'low':0x1004ddf2c,'upper':0x1005c3030,'u32':0x1004df94c,'span':0x100531578,'known_other':0x10052f47c,'stage':0x100609e2c,'select':0x100801774,'caller':0x1004e1f94,'error':0x100941a74}
EDGES={'mode':[0x2122],'head':[0x8754,0x8755],'lookup_call':[0x18e2],'lookup_entry':[0xc157,0xc1ca],'lookup_return':[0x3c37,0x432d],'buffer':[0x94f5,0x9536],'minimum':[0x2167,0x7a3c],'word_prepare':[0x2520],'word_return':[0x1f39],'tag_return':[0x3a31],'word_call':[0x8c3f],'extent':[0x8724,0x8725],'fit':[0x6210],'type':[0x8ba2,0x8bae],'low':[0x8aed,0xacbf],'upper':[0x814b,0x814f],'u32':[0x2167,0x9fe3],'span':[0x62f8,0x658c],'known_other':[0x3c37],'stage':[0x4b1d,0x4b59],'select':[0x342d,0x344e],'caller':[0x3884],'error':[0xc04f]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={};edges=[];ixs={0x130b,0xf3,0x218,0x100};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in BLOCKS.items():
  f=block(a,0x3000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f;mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES[n]:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix));ixs.add(ix);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
  ii=list(dc.disasm(bytes.fromhex(f['bytes']),a));assert not any('sp'in{i.reg_name(r)for r in i.regs_access()[1]}for i in ii);cc=[i.mnemonic for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','svc','hvc','smc')];assert cc==['braa']
 for n,a,z in [('context_copy',0x1006c8a10,0x1006c8a6c),('context_default',0x100939f64,0x100939f94)]:
  raw=IMAGE.read(a,z-a);fs[n]={'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':h(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)],'scope':'Explicit source prefix; whole initializer and incoming-context identity are excluded.'}
 prep=block(0x1006f6bf0,0x4000);prep['sha256']=h(bytes.fromhex(prep['bytes']));assert len(prep['instructions'])==386
 old=json.loads(read(ROOT/'daemon_reader_context_footprint_source.json'));assert prep==old['preparation']
 rec=[]
 for fn,names in [('daemon_constructor_lookup_source.json',None),('daemon_existing_scalar_reader_source.json',['word','tag','word_call'])]:
  obj=json.loads(read(ROOT/fn))
  for n,f in obj['fragments'].items():
   if names is not None and n not in names:continue
   raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;rec.append({'file':fn,'fragment':n,'start':f['start'],'bytes_checked':len(raw),'sha256':h(raw)})
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(ixs)]
 census=scan([{'input':n,'offset_bytes':o,'extent_bytes':w}for n,o,w in [('N19_BASE',0x3a18,8),('N19_F',0x53ac,4),('N19_LEN',0x285c,4)]]);assert len(census['candidates'])==12
 deps=['daemon_reader_outer_lifecycle_source.json','daemon_reader_outer_lifecycle_checks.json','daemon_reader_u64_codec_source.json','daemon_reader_u64_codec_checks.json','daemon_reader_context_footprint_source.json','daemon_reader_context_footprint_checks.json','daemon_constructor_lookup_source.json','daemon_constructor_lookup_checks.json','daemon_existing_scalar_reader_source.json','daemon_existing_scalar_reader_checks.json','daemon_reader_container_origins_source.json','daemon_reader_container_origins_checks.json','recover_daemon_reader_context_footprint.py','validate_daemon_existing_scalar_reader.py','validate_daemon_reader_outer_lifecycle.py','daemon_receive_fixups.txt']
 counts={'source_fragments':len(fs),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'branch_terminated_ranges':len(BLOCKS),'explicit_prefixes':2,'preparation_instructions':386,'preparation_bytes':1544,'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(q['bytes_checked']for q in rec),'candidate_frame_writers':12,'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'preparation':prep,'preparation_write_ledger':old['write_ledger'],'preparation_read_ledger':old['read_ledger'],'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(q['slot'],16)for q in ptr}),'prior_recaptures':rec,'writer_candidates':census,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
