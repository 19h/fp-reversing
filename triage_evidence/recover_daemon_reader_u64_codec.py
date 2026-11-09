#!/usr/bin/env python3
"""Static full eight-byte reader, literal/residual key origins and N19 value staging."""
import json,re,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,block,h,FLAGS
from daemon_receive_tools import verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read,sha
P='daemon_reader_u64_codec'
SCOPE='Conditional complete eight-byte address-mask reader and merge,actual key-origin/liveness join,N19 raw64 staging/composition with the established writer,and source allocation-to-container/publication provenance. No native pointer/lifetime/PAC/endpoint/transport or complete parser proof.'
BLOCKS={'prepare':0x1006f6bf0,'reader':0x100588cb0,'word':0x100800004,'extent':0x100499044,'caller':0x1004a4de8,'returned':0x1004cdeac,'join':0x1004730ec,'pack':0x10056deb8,'writer_caller':0x10053f020,'allocation_result':0x1004958d4,'zero_container':0x1005b078c,'loop':0x1004ddaec,'empty':0x1005588b4,'success':0x1007f6f54,'output':0x10058816c,'outer_return':0x1005b95e8}
EDGES={'prepare':[0x8c3f],'reader':[0x8c4],'word':[],'extent':[0x851d,0x185d],'caller':[0xbe63],'returned':[0x746b],'join':[0x7042,0x70a6],'pack':[0xb8e4,0xb913],'writer_caller':[0x7d2d],'allocation_result':[0xc4dd,0xc4e0],'zero_container':[0x3599],'loop':[0xb350,0xb358],'empty':[0x3298],'success':[0x751d],'output':[0x7613],'outer_return':[]}
LIVE=[0x1005f4734,0x100574bf4,0x1005fbaa0,0x1006116d0,0x100499044]
KEYS={3:0xeb8e58819a88bf30,6:0x9032dc5079388982,9:0x1dd3a2cc9b1a2a60,19:0x622c5d3364e5d59f,21:0x4f99108510ad96e0,23:0x7faaf81a732f68b4,25:0xe70987b7a1f527b0,26:0xa7bebfcf1750d389,27:0x144db9b1af6b5721,28:0x324a764c67af2e0e}
def states(f):
 known=dict(KEYS);out={};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for i in dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)):
  out[hex(i.address)]={str(k):hex(v)for k,v in sorted(known.items())};old=dict(known);p=i.op_str.split(', ')
  for r in i.regs_access()[1]:
   n=i.reg_name(r)
   if re.fullmatch('[xw][0-9]+',n):known.pop(int(n[1:]),None)
  if i.mnemonic=='mov'and len(p)==2 and p[0][0]in'xw'and p[1].startswith('#'):known[int(p[0][1:])]=int(p[1][1:],0)&((1<<(32 if p[0][0]=='w'else 64))-1)
  if i.mnemonic=='movk':
   r=int(p[0][1:]);shift=int(p[2].split('#')[1],0)
   if r in old:known[r]=(old[r]&~(65535<<shift))|(int(p[1][1:],0)<<shift)
 return out
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';fs={};edges=[];indices={0x8c4,0xbe63,0x7d2d,0x1351};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in BLOCKS.items():
  f=block(a,0x5000);f['sha256']=h(bytes.fromhex(f['bytes']));fs[n]=f;assert f['instructions'][-1]['mnemonic']=='braa';mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES[n]:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7);indices.add(ix);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
  cc=[]
  for i in dc.disasm(bytes.fromhex(f['bytes']),a):
   assert 'sp'not in{i.reg_name(r)for r in i.regs_access()[1]}
   if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','svc'):cc.append(i.mnemonic)
  assert cc==['braa']
 old=json.loads(read(ROOT/'daemon_constructor_lookup_source.json'));f=old['fragments']['prepare_decoder'];a,z=0x1006f70d8,0x1006f71f0;raw=IMAGE.read(a,z-a);fs['literal_tail']={'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':h(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)],'scope':'Explicit half-open literal-origin cut.'};assert fs['word']==old['fragments']['decode']
 raw=IMAGE.read(0x1005a2c2c,0x1005a2c68-0x1005a2c2c);fs['writer_entry']={'start':'0x1005a2c2c','end':'0x1005a2c68','bytes':raw.hex(),'sha256':h(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,0x1005a2c2c)],'scope':'Explicit half-open saved-value load cut.'}
 for name,a,z in[('allocation_prefix',0x100495808,0x10049582c),('allocation_args',0x1004958c8,0x1004958d0),('comparison_store',0x1004d3e1c,0x1004d3e20)]:
  raw=IMAGE.read(a,z-a);fs[name]={'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':h(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)],'scope':'Explicit saved-comparison-context store.'if name=='comparison_store'else'Explicit normal-allocation ABI prefix/argument cut;callee is not executed.'}
 gap=IMAGE.read(0x10049582c,0x1004958c8-0x10049582c)
 for i in dc.disasm(gap,0x10049582c):
  assert not({'sp'}|{p+str(j)for p in('x','w')for j in[20,22,23,24]})&{i.reg_name(r)for r in i.regs_access()[1]}
  assert not i.mnemonic.startswith(('b.','cb','tb'))and i.mnemonic not in('b','bl','br','blr','braa','blraa','ret','svc')
 live=[]
 for a in LIVE:
  f=block(a,0x4000);wr=set()
  for i in dc.disasm(bytes.fromhex(f['bytes']),a):wr|={i.reg_name(r)for r in i.regs_access()[1]}
  need=(set(KEYS)-{3})|{20};assert not{p+str(j)for p in('x','w')for j in need}&wr;live.append({'start':hex(a),'bytes':f['bytes'],'sha256':h(bytes.fromhex(f['bytes'])),'preserved_keys':sorted(need),'written_registers':sorted(wr)})
 ii=fs['reader']['instructions'];seeds=[j for j,i in enumerate(ii)if i['mnemonic']=='and'and'#0xfffffffffffffff8'in i['operands']];eors=[j for j,i in enumerate(ii)if i['mnemonic']=='eor'and'ror #61'in i['operands']];sels=[j for j,i in enumerate(ii)if i['mnemonic']=='ubfiz'];assert len(seeds)==len(sels)==8 and len(eors)==48
 refs=[]
 for fn,names in [('daemon_reader_value_consumers_source.json',['0x100588cb0']),('daemon_typed_scalar_source.json',['u64_writer'])]:
  obj=json.loads(read(ROOT/fn))
  if names:
   for n in names:
    f=obj['fragments'][n];raw=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(raw))==raw;refs.append({'file':fn,'fragment':n,'bytes_checked':len(raw),'sha256':h(raw)})
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)]
 deps=['daemon_reader_container_origins_source.json','daemon_reader_container_origins_checks.json','daemon_reader_context_footprint_source.json','daemon_reader_value_consumers_source.json','daemon_reader_value_consumers_checks.json','daemon_constructor_lookup_source.json','daemon_constructor_lookup_checks.json','daemon_reader_record_payloads_source.json','daemon_reader_record_payloads_checks.json','daemon_typed_scalar_source.json','daemon_typed_scalar_checks.json','daemon_reader_typed_dispatch_source.json','daemon_reader_typed_dispatch_checks.json','daemon_reader_record_headers_source.json','verify_daemon_reader_record_payloads_publication.py','daemon_receive_fixups.txt']
 counts={'source_fragments':len(fs),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'branch_terminated_ranges':len(BLOCKS),'explicit_source_cuts':len(fs)-len(BLOCKS),'prior_source_ranges_recaptured':len(refs),'reader_byte_loads':8,'reader_seed_parts':8,'reader_round_parts':56,'key_liveness_ranges':len(live),'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(r['slot'],16)for r in ptr}),'required_reader_key_values':{str(k):hex(v)for k,v in KEYS.items()},'constant_states_before_reader_sites':states(fs['reader']),'key_liveness_ranges':live,'allocation_preservation_gap':{'start':'0x10049582c','end':'0x1004958c8','bytes':gap.hex(),'sha256':h(gap),'preserved_register_numbers':[20,22,23,24]},'reader_parts':{'seed_indices':seeds,'round_markers':eors,'selection_indices':sels,'last_word_xor_delta':'0x9898989898989898'},'prior_source_recaptures':refs,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
