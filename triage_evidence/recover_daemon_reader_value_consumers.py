#!/usr/bin/env python3
"""Original-source scalar consumers,variant join and special pointer output."""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,block,sha,h,FLAGS
from recover_daemon_context_input_producers import scan
from daemon_receive_tools import verify_original_fixups
P='daemon_reader_value_consumers'
SCOPE='Five scalar return/staging contracts,two converged caller flows and flag-selected equality predicates,N19 preceding-word producer/common variant prefix/special pointer publication,and eight-byte reader footprint/return ABI. No complete eight-byte transform,ordinary result publication,native ownership/cache/admission/PAC/endpoint or daemon-kext pairing proof.'
RETURNS={'N19':(0x100532b34,[0x746b]),'N20':(0x1005705f4,[0x9bfc,0x54d2]),'N21':(0x10052c2bc,[0xb98a,0x3631]),'N22':(0x100509164,[0x6c94,0x6959]),'N23':(0x10047c454,[0x7d48,0x2a94])}
EXTRA={0x1004d5adc:[0x51e2,0x521b],0x1007f43b4:[0x5f85,0x5f87],0x100540018:[0x9790,0x2fc8],0x1005fa760:[0xcb5d,0x6959],0x1005cf720:[0x1f39],0x100588cb0:[0x8c4],0x1004cdeac:[0x746b],0x1004730ec:[0x7042,0x70a6],0x10056deb8:[0xb8e4,0xb913],0x1007f6f54:[0x751d],0x10058816c:[0x7613]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 old=json.loads((ROOT/'daemon_reader_typed_dispatch_source.json').read_text());fs={};edges=[];indices={0xaf};families=[]
 for n,(a,ixs)in RETURNS.items():
  row=next(r for r in old['families']if r['name']==n);assert row['u32_return']==hex(a);families.append({'name':n,'entry':hex(a),'indices':[hex(ix)for ix in ixs],'parent':row})
 for a,ixs in [(a,ixs)for a,ixs in RETURNS.values()]+list(EXTRA.items()):
  f=block(a,0x4000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[hex(a)]=f;mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in ixs:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7);indices.add(ix);edges.append({'source':hex(a),'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
 assert FIXUPS[TABLE+8*0xaf]['target']==0x1005cf720
 census=scan([{'input':'H19','offset_bytes':0x9584,'extent_bytes':4}]);cc=census['candidates'];assert len(cc)==1 and cc[0]['source_store']=='0x1005cf730'and cc[0]['width_bytes']==4
 n19=next(r for r in old['families']if r['name']=='N19');span={a:old['fragments'][a]for a in[n19['parent'][k]for k in['gate','fit_bridge','type_prefix']]+[n19['high'],n19['span_exact'],n19['span_targets'][0]]}
 for f in [old['preparation']]+list(span.values()):assert IMAGE.read(int(f['start'],16),len(bytes.fromhex(f['bytes'])))==bytes.fromhex(f['bytes'])
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;controls={};target_writes=[]
 for n,f in fs.items():
  ii=list(dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)));cc=[{'site':hex(i.address),'mnemonic':i.mnemonic}for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','retaa','svc','hvc','smc')];assert len(cc)==1 and cc[0]['mnemonic']=='braa';assert not any('sp'in{i.reg_name(x)for x in i.regs_access()[1]}for i in ii);controls[n]=cc
  if n=='0x100588cb0':
   assert not any(i.mnemonic.startswith('st')for i in ii);target_writes=[hex(i.address)for i in ii if {'x8','w8'}&{i.reg_name(x)for x in i.regs_access()[1]}];assert target_writes==['0x100588cb4']
 pointers=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)];deps=['daemon_reader_typed_dispatch_source.json','daemon_reader_typed_dispatch_checks.json','daemon_reader_extent_families_source.json','daemon_existing_scalar_reader_source.json','daemon_existing_scalar_reader_checks.json','recover_daemon_context_input_producers.py','recover_daemon_reader_context_footprint.py','validate_daemon_reader_extent_families.py','validate_daemon_existing_scalar_reader.py','validate_daemon_reader_context_footprint.py','daemon_receive_fixups.txt'];counts={'families':len(families),'source_fragments':len(fs),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'span_context_fragments':len(span),'span_context_instructions':sum(len(f['instructions'])for f in span.values()),'preparation_instructions':len(old['preparation']['instructions']),'pointer_records':len(pointers),'branch_slot_modifier_matches':len(edges),'eight_byte_helper_instructions':len(fs['0x100588cb0']['instructions']),'source_SP_writes':0}
 ref=json.loads((ROOT/'daemon_constructor_inputs_source.json').read_text())['fragments']['entry'];assert IMAGE.read(int(ref['start'],16),len(bytes.fromhex(ref['bytes'])))==bytes.fromhex(ref['bytes']);deps+=['daemon_constructor_inputs_source.json','daemon_constructor_inputs_checks.json']
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'families':families,'fragments':fs,'span_context':span,'preparation':old['preparation'],'preparation_write_ledger':old['preparation_write_ledger'],'preceding_word_writer_census':census,'constructor_field_reference':{'entry':ref,'scope':'Byte-recaptured prior constructor entry reference only;not counted in new translated-site coverage. Prior constructor input proof supplies its field offsets/widths. Shared complete object/type equivalence is not proved.'},'branch_edges':edges,'pointer_records':pointers,'original_fixup_checks':verify_original_fixups({int(q['slot'],16)for q in pointers}),'control_ledger':controls,'eight_byte_return_target_writes':target_writes,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
