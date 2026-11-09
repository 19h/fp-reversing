#!/usr/bin/env python3
"""Original-source five-reader extent/type-prefix contracts; no target execution."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,block,sha,h,FLAGS
from daemon_receive_tools import verify_original_fixups
P='daemon_reader_extent_families'
SCOPE='Five conditional normalized extent gates,composed fixed bridges,signed-low16 tag prefixes and first failure effects. No full accessor semantics,all-alias/current-frame initialization,native PAC/endpoint or successful daemon-kext exchange proof.'
ROWS=[
 ('N19','N0','N24',0x830,0x661a590b302baf9c,0x9590,0x1005f4734,0x8661,0x86a0,0x100574bf4,0xb6a4,0x1005fbaa0,0x9b8),
 ('N20','N1','N2',0x8e8,0x150c66978fb97938,0x8f80,0x100549e08,0x7aae,0x7a75,0x1005f96fc,0x35a1,0x10053063c,0x9a0),
 ('N21','N3','N14',0x8d0,0x0e56372fd4e50e7b,0x8f70,0x1005937a4,0x8907,0x88f4,0x1005ef6ac,0xae84,0x10060542c,0x990),
 ('N22','N4','N15',0x8a8,0xec7b0374217183cf,0x8f58,0x100527de0,0x2c41,0x2c8b,0x10054c07c,0xa598,0x1005ad68c,0x998),
 ('N23','N5','N16',0x880,0x42f093c391145ff4,0x8f48,0x1005450dc,0x3695,0x36bf,0x1005aaa28,0x9fb9,0x100552738,0x988)]
TYPE_PAIRS={'N19':(0x8055,0x806f),'N20':(0x5ad8,0x5ad5),'N21':(0xabb5,0xabc6),'N22':(0x6c67,0x6c8f),'N23':(0xa170,0xa15a)}
BAD_PAIRS={'N19':(0x3ad1,), 'N20':(0x30e4,), 'N21':(0xc944,0xc935), 'N22':(0x30e4,), 'N23':(0x33fb,0x33ce)}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 ctx=json.loads((ROOT/'daemon_reader_context_footprint_source.json').read_text());old=json.loads((ROOT/'daemon_context_input_producers_source.json').read_text());prep=ctx['preparation'];assert IMAGE.read(int(prep['start'],16),len(bytes.fromhex(prep['bytes'])))==bytes.fromhex(prep['bytes'])
 fragments={};families=[];indices=set();edges=[]
 def capture(a):
  n=hex(a)
  if n not in fragments:
   f=block(a,0x4000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fragments[n]=f
  return n
 def edge(a,ix):
  f=fragments[hex(a)];i=f['instructions'];mod=int(i[-2]['operands'].split('#')[1],0);slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7);indices.add(ix);target=FIXUPS[slot]['target'];q={'source':hex(a),'branch_site':i[-1]['ea'],'index':hex(ix),'slot':hex(slot),'target':hex(target),'IA_diversity':hex(mod)};edges.append(q);return q
 for name,cur,lim,koff,kbias,eoff,a,good,bad,bridge,tix,typ,tagoff in ROWS:
  ref=next(r for r in old['tag_return_interfaces']if r['target']==name);assert ref['next_word_return_target']==hex(a)and ref['next_word_key_frame_offset']==hex(koff)and ref['working_tag_frame_offset']==hex(tagoff)
  capture(a);capture(bridge);capture(typ);ge=edge(a,good);be=edge(a,bad);assert ge['target']==hex(bridge);capture(int(be['target'],16));te=edge(bridge,tix);assert te['target']==hex(typ)
  type_edges=[edge(typ,ix)for ix in TYPE_PAIRS[name]]
  reject_edges=[edge(int(be['target'],16),ix)for ix in BAD_PAIRS[name]]
  families.append({'name':name,'cursor_input':cur,'limit_input':lim,'length_key_cache_offset':hex(koff),'length_key_bias':hex(kbias),'saved_end_offset':hex(eoff),'gate':hex(a),'fit_index':hex(good),'reject_index':hex(bad),'fit_bridge':hex(bridge),'reject_first':be['target'],'type_index':hex(tix),'type_prefix':hex(typ),'tag_low_index':hex(TYPE_PAIRS[name][0]),'tag_high_index':hex(TYPE_PAIRS[name][1]),'tag_low_frontier':type_edges[0]['target'],'tag_high_frontier':type_edges[1]['target'],'reject_next_indices':[q['index']for q in reject_edges],'reject_next_frontiers':[q['target']for q in reject_edges],'working_tag_offset':hex(tagoff),'phase_u32':'0x6cf4','same_active_frame_initialization_proved':False})
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;controls={};loads={}
 for name,f in fragments.items():
  ii=list(dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)));cc=[{'site':hex(i.address),'mnemonic':i.mnemonic}for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','retaa','svc','hvc','smc')];assert len(cc)==1 and cc[0]['mnemonic']=='braa';controls[name]=cc
  assert not any({'sp'}&{i.reg_name(x)for x in i.regs_access()[1]}for i in ii)
  loads[name]=[i for i in f['instructions']if i['mnemonic'].startswith(('ldr','ldur'))]
 pointers=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)]
 deps=['daemon_reader_context_footprint_source.json','daemon_reader_context_footprint_checks.json','daemon_context_input_producers_source.json','daemon_context_input_producers_checks.json','daemon_existing_scalar_reader_source.json','daemon_existing_scalar_reader_checks.json','daemon_receive_fixups.txt','recover_daemon_reader_context_footprint.py','validate_daemon_existing_scalar_reader.py']
 counts={'families':len(families),'source_fragments':len(fragments),'source_instruction_instances':sum(len(f['instructions'])for f in fragments.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fragments.values()),'preparation_instructions':len(prep['instructions']),'pointer_records':len(pointers),'branch_slot_modifier_matches':len(edges),'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'families':families,'preparation':prep,'preparation_read_ledger':ctx['read_ledger'],'preparation_write_ledger':ctx['write_ledger'],'fragments':fragments,'branch_edges':edges,'pointer_records':pointers,'original_fixup_checks':verify_original_fixups({int(r['slot'],16)for r in pointers}),'control_ledger':controls,'load_ledger':loads,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
