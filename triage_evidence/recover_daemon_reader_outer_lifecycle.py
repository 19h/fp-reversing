#!/usr/bin/env python3
"""Read-only source recovery for the reader's outer allocation and publication."""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,block,selected,h,FLAGS
from recover_daemon_context_input_producers import scan
from daemon_receive_tools import verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read,sha
P='daemon_reader_outer_lifecycle'
SCOPE='Conditional 128 B outer allocation, selected context-field transfer, N19 parent/output and control predicate, raw-result staging/publication, cleanup pointer-cell epoch and local cursor restoration. No continuous parser/initializer, native ownership/PAC, complete cleanup, external publication or daemon-kext pairing proof.'
BLOCKS={'setup':0x1009638c0,'allocate':0x1008c3fac,'zero':0x1008a21a8,'stage':0x100609e2c,'select':0x100801774,'caller':0x1004e1f94,'returned':0x100975d34,'publish':0x100918d7c,'dispose':0x100a0bf60,'cleanup':0x1007322cc,'restore':0x10092757c,'after':0x100908b50}
EDGES={'setup':[0x3977,0x3986],'allocate':[0x539e,0x53a5],'zero':[0xa3b3,0xa3f0],'stage':[0x4b1d,0x4b59],'select':[0x342d,0x344e],'caller':[0x3884],'returned':[0xc022,0xc04f],'publish':[0x539e],'dispose':[0x1fbb],'cleanup':[0x5086,0x5096],'restore':[0x4f91],'after':[0xb2cf,0xb2cf^(((0xb2cf^0xa9a3)+11)^0x1b5e)]}
CALLS={'setup':0x10096398c,'allocate':0x1008c4010}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={};edges=[];indices={0xb9a}
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in BLOCKS.items():
  f=block(a,0x2000);assert f['instructions'][-1]['mnemonic']=='braa';f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f
  mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES[n]:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and ((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix),hex(mod));indices.add(ix);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
  ii=list(dc.disasm(bytes.fromhex(f['bytes']),a));assert not any('sp'in{i.reg_name(r)for r in i.regs_access()[1]}for i in ii)
  cc=[(i.address,i.mnemonic)for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','svc','hvc','smc')]
  expected=([(CALLS[n],'blraa')]if n in CALLS else[])+[(int(f['instructions'][-1]['ea'],16),'braa')];assert cc==expected
 a,z=0x1006c8a10,0x1006c8a6c;raw=IMAGE.read(a,z-a);fs['copy_fields']={'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':h(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)],'scope':'Explicit field-transfer prefix only; subsequent obfuscated byte-copy loops are excluded.'}
 banks=[]
 for n,l,r,k,add,pc,mod,target in [('fill',0x100fc4230,0x101031fa0,0xf3,0xcc58,0x10096398c,0xac7d,'0x10046faf8'),('allocation',0x100e99a00,0x100f4e390,0x9c,0xcbdf,0x1008c4010,0x6aa4,'libSystem/_malloc')]:
  b=selected(l,r,k,add,TABLE,0);lb,rb=IMAGE.read(l,256),IMAGE.read(r,256);vv=[i^rb[lb[i]^k]for i in range(256)];assert len(set(vv))==1 and b['target']==target
  assert next(CS.disasm(IMAGE.read(pc-4,4),pc-4)).op_str=='x17, #'+hex(mod)
  b.update(role=n,left_bytes=lb.hex(),right_bytes=rb.hex(),results_256=vv,key_u8=k,call_site=hex(pc),modifier_u16=mod);banks.append(b);indices.add(int(b['index'],16))
 census=scan([{'input':n,'offset_bytes':o,'extent_bytes':w}for n,o,w in [('OBJECT',0x1ae8,8),('OUT',0x1d60,8),('RETSTATUS',0x5f60,4)]])
 assert len(census['candidates'])==18
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)]
 old=json.loads(read(ROOT/'daemon_reader_container_origins_source.json'));assert fs['caller']=={**old['fragments']['caller16'],'sha256':h(bytes.fromhex(old['fragments']['caller16']['bytes']))}
 deps=['daemon_reader_u64_codec_source.json','daemon_reader_u64_codec_checks.json','daemon_reader_container_origins_source.json','daemon_reader_container_origins_checks.json','daemon_builder_owner_join_source.json','daemon_builder_owner_join_checks.json','daemon_collection_retirement_source.json','daemon_collection_retirement_checks.json','daemon_frame_entry_contracts.json','recover_daemon_context_input_producers.py','validate_daemon_reader_container_origins.py','daemon_receive_fixups.txt']
 counts={'source_fragments':len(fs),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'branch_terminated_ranges':len(BLOCKS),'explicit_prefixes':1,'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'bank_inputs_checked':512,'candidate_frame_writers':18,'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(p['slot'],16)for p in ptr}),'banks':banks,'writer_candidates':census,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
