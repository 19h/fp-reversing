#!/usr/bin/env python3
"""Original-source N19 admission,record allocations and common header writer joins."""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,CS,block,sha,h,FLAGS,selected
from daemon_receive_tools import verify_original_fixups
P='daemon_reader_record_headers'
SCOPE='Conditional N19 cursor/header admission,read-key/cache provenance,32 B node and extent+10 buffer allocation contracts,and shared header-writer joins. No payload completion/list insertion/back-edge/native cleanup/owner/PAC/daemon-kext pairing proof.'
BLOCKS={'loop':0x1004ddaec,'buffer':0x10052b478,'admit':0x1004dbcf8,'read_call':0x1004f8144,'read_prepare':0x1006f6bf0,'read_tag':0x1005122cc,'length_guard':0x1005bea60,'node_alloc':0x1005f3b24,'record_alloc':0x1004d617c,'write_call':0x1005bfca8,'write_prepare':0x1008ecb78,'after_identifier':0x1007b1fbc,'after_tag':0x1005ffd64,'word_call':0x100615004,'after_extent':0x100517a0c}
EDGES={'loop':[0xb350,0xb358],'buffer':[0x6ff5,0x701f],'admit':[0x185d,0x1ba2],'read_call':[0x2520],'read_prepare':[0x8c3f],'read_tag':[0x1fa],'length_guard':[0x8753,0x701f],'node_alloc':[0x7b3b,0x7b61],'record_alloc':[0x27f2,0x27fc],'write_call':[0x54e5],'write_prepare':[0x9da7],'after_identifier':[0x2cff],'after_tag':[0x1824],'word_call':[0x9da7],'after_extent':[0xadb6]}
CALLS={'node_alloc':0x1005f3bac,'record_alloc':0x1004d62ec}
BANKS=[('node',0x100fc4230,0x101031fa0,0xf3,0xcbca),('record',0x100fc4130,0x101031ea0,0xa3,0xcb9b)]
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';fs={};edges=[];indices={0xaf,0x27b,0xa48,0x29b,0xcc0d}
 for n,a in BLOCKS.items():
  f=block(a,0x4000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f;mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES[n]:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and((w>>32)&65535)==mod and not((w>>48)&7);indices.add(ix);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
 banks=[]
 for n,l,r,k,add in BANKS:
  b=selected(l,r,k,add,TABLE,0);lb,rb=IMAGE.read(l,256),IMAGE.read(r,256);v=[i^rb[lb[i]^k]for i in range(256)];assert len(set(v))==1 and b['target']=='libSystem/_malloc'and b['slot']=='0x10109ff58';b.update(name=n,left_bytes=lb.hex(),right_bytes=rb.hex(),key_u8=k,additive_u32=add,results_256=v);banks.append(b)
 dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True;controls={}
 for n,f in fs.items():
  ii=list(dc.disasm(bytes.fromhex(f['bytes']),int(f['start'],16)));cc=[{'site':hex(i.address),'mnemonic':i.mnemonic}for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','retaa','svc','hvc','smc')];assert not any('sp'in{i.reg_name(x)for x in i.regs_access()[1]}for i in ii)
  if n in CALLS:assert cc==[{'site':hex(CALLS[n]),'mnemonic':'blraa'},{'site':f['instructions'][-1]['ea'],'mnemonic':'braa'}]
  else:assert len(cc)==1 and cc[0]['mnemonic']=='braa'
  controls[n]=cc
 refs=[]
 for fn,names in [('daemon_header_codec_source.json',['word','tag']),('daemon_existing_scalar_reader_source.json',['word']),('daemon_reader_extent_families_source.json',['0x1005f4734'])]:
  o=json.loads((ROOT/fn).read_text())
  for n in names:
   f=o['fragments'][n];bb=bytes.fromhex(f['bytes']);assert IMAGE.read(int(f['start'],16),len(bb))==bb;refs.append({'file':fn,'fragment':n,'bytes_checked':len(bb),'sha256':h(bb),'scope':'Prior source reference;not counted in new translated-site coverage.'})
 hdr=json.loads((ROOT/'daemon_header_codec_source.json').read_text());reader=json.loads((ROOT/'daemon_existing_scalar_reader_source.json').read_text());assert fs['write_prepare']==hdr['fragments']['key_setup']and fs['read_prepare']==reader['fragments']['prepare']and fs['read_tag']==reader['fragments']['tag']
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(indices)]
 deps=['daemon_reader_container_origins_source.json','daemon_reader_container_origins_checks.json','daemon_reader_value_consumers_source.json','daemon_reader_value_consumers_checks.json','daemon_header_codec_source.json','daemon_header_codec_checks.json','daemon_existing_scalar_reader_source.json','daemon_existing_scalar_reader_checks.json','daemon_reader_context_footprint_source.json','daemon_reader_context_footprint_checks.json','daemon_reader_extent_families_source.json','daemon_reader_extent_families_checks.json','validate_daemon_reader_container_origins.py','validate_daemon_header_codec.py','validate_daemon_existing_scalar_reader.py','daemon_receive_fixups.txt']
 counts={'source_fragments':len(fs),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'allocation_call_boundaries':2,'bank_inputs_checked':512,'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'prior_source_ranges_recaptured':len(refs),'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'call_boundaries':{n:hex(pc)for n,pc in CALLS.items()},'banks':banks,'pointer_records':ptr,'original_fixup_checks':verify_original_fixups({int(r['slot'],16)for r in ptr}),'control_ledger':controls,'prior_source_recaptures':refs,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
