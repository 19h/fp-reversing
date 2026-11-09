#!/usr/bin/env python3
"""Original-file outer wire-to-record ingress. No target execution or IDB effects.
O(B+I+256+R) time and space for retained source bytes B,instructions I,recaptures R.
"""
import json,capstone
from recover_daemon_xpc_core_bridge import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,block,h,FLAGS,selected
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_receive_tools import verify_original_fixups
P='daemon_outer_record_ingress'
SCOPE='Selected outer INPUT/encoded-length/OBJ+0 route to shared plain-wire parser: ten-byte header, exact u32/u64/span type and extent gates, scalar constructor XOR operands, borrowed span, cursor loop, zero-ID span termination and local output. This is a source component contract; native ingress/owners,complete constructor/parser/cleanup and daemon-kext pairing remain unproved.'
BLOCKS={'caller':0x1006c82e4,'entry':0x1006997a4,'initialize':0x1008c3880,'loop':0x1006d54e8,'pointer':0x1008cf2d8,'minimum':0x10076b268,'length':0x100670430,'header':0x100705408,'type_partition':0x100842bd0,'type_u32':0x100893a90,'type_upper':0x100750e08,'type_u64':0x1007c7954,'type_span':0x100768270,'extent_u32':0x1009b66b4,'extent_u64':0x100778bc0,'read_u32':0x1007079b4,'read_u64':0x100838b54,'advance':0x1008f0cb0,'span':0x1008c0380,'sentinel':0x1007481bc,'generic':0x10097b9b0,'generic_return':0x10084d5d0,'exhausted':0x1006c47bc,'publish':0x100758ae8,'return':0x1008c8b80,'outer_return':0x1008b3a7c,'error':0x1008f045c}
EDGES={'caller':[0x18bd],'entry':[0x7081,0x70bc],'initialize':[0x1892],'loop':[0xa633,0xa62b],'pointer':[0x9b50,0x9b55],'minimum':[0x2496,0x1a25],'length':[0xa46c,0xa49f],'header':[0x5ac3],'type_partition':[0x4232,0x4291],'type_u32':[0x7700,0x1a25],'type_upper':[0x3139,0x313c],'type_u64':[0x65fc,0x1a25],'type_span':[0x1a2b,0x1a25],'extent_u32':[0xca49,0xa49f],'extent_u64':[0x3124,0x1a25],'read_u32':[0x8868],'read_u64':[0x8868],'advance':[0x3eff],'span':[0x3eff,0x3f49],'sentinel':[0x3b30],'generic':[0x5eb2],'generic_return':[0x8784,0x1a25],'exhausted':[0x3b30],'publish':[0x188e],'return':[],'outer_return':[0xc6db,0x445a],'error':[0x3ad1]}
def build():
 assert sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 fs={};edges=[];ixs={0x1649,0x228,0xcc0d};dc=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);dc.detail=True
 for n,a in BLOCKS.items():
  f=block(a,0x3000);f['sha256']=h(bytes.fromhex(f['bytes']));assert f['instructions'][-1]['mnemonic']=='braa';fs[n]=f
  mod=int(f['instructions'][-2]['operands'].split('#')[1],0)
  for ix in EDGES[n]:
   slot=TABLE+8*ix;w=int.from_bytes(IMAGE.read(slot,8),'little');assert w>>63 and ((w>>32)&65535)==mod and not((w>>48)&7),(n,hex(ix),hex(w));ixs.add(ix);edges.append({'fragment':n,'index':hex(ix),'slot':hex(slot),'target':hex(FIXUPS[slot]['target']),'IA_diversity':hex(mod)})
  ii=list(dc.disasm(bytes.fromhex(f['bytes']),a));assert not any('sp'in{i.reg_name(r)for r in i.regs_access()[1]}for i in ii)
  assert [i.mnemonic for i in ii if i.mnemonic.startswith(('b.','cb','tb'))or i.mnemonic in('b','bl','br','blr','braa','blraa','ret','retab','svc','hvc','smc')]==(['blraa','braa']if n=='entry'else['braa'])
 bank=selected(0x100e99a00,0x100f4e390,0x6d,0xcb3d,TABLE,0);assert bank['index']=='0xcc0d'and bank['target']=='libSystem/_malloc';bank.update(left_bytes=IMAGE.read(0x100e99a00,256).hex(),right_bytes=IMAGE.read(0x100f4e390,256).hex())
 # Explicit parentheses keep bank address arithmetic unambiguous.
 left=bytes.fromhex(bank['left_bytes']);right=bytes.fromhex(bank['right_bytes']);bank['results_256']=[j^right[left[j]^0x6d]for j in range(256)];assert set(bank['results_256'])=={0xd0}
 rec=[];prior=['daemon_constructor_callers_source.json','daemon_constructor_inputs_source.json','daemon_payload_codec_source.json','daemon_reader_outer_lifecycle_source.json']
 def walk(obj,fn,path=''):
  if isinstance(obj,dict):
   raw=obj.get('bytes',obj.get('bytes_hex'));a=obj.get('start')
   if isinstance(raw,str)and isinstance(a,str)and a.startswith('0x'):
    bb=bytes.fromhex(raw);assert IMAGE.read(int(a,16),len(bb))==bb,(fn,path);rec.append({'file':fn,'path':path,'start':a,'bytes_checked':len(bb),'sha256':h(bb)})
   for k,v in obj.items():walk(v,fn,path+'/'+k)
  elif isinstance(obj,list):
   for j,v in enumerate(obj):walk(v,fn,path+'/'+str(j))
 for fn in prior:walk(json.loads(read(ROOT/fn)),fn)
 ptr=[{'index':hex(ix),'slot':hex(TABLE+8*ix),'raw_bytes':IMAGE.read(TABLE+8*ix,8).hex(),'fixup':FIXUPS[TABLE+8*ix]}for ix in sorted(ixs)]
 deps=prior+['daemon_constructor_callers_checks.json','daemon_payload_codec_checks.json','daemon_reader_outer_lifecycle_checks.json','validate_daemon_reader_outer_lifecycle.py','validate_daemon_existing_scalar_reader.py','validate_daemon_constructor_inputs.py','validate_daemon_constructor_lookup.py','validate_daemon_reader_container_origins.py','daemon_receive_fixups.txt']
 counts={'source_fragments':len(fs),'source_instruction_instances':sum(len(f['instructions'])for f in fs.values()),'source_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs.values()),'branch_terminated_ranges':len(fs),'pointer_records':len(ptr),'branch_slot_modifier_matches':len(edges),'bank_inputs_checked':256,'prior_ranges_recaptured':len(rec),'prior_bytes_recaptured':sum(q['bytes_checked']for q in rec),'source_SP_writes':0}
 return {'generator_sha256':sha(__file__),'static_scope':SCOPE,'daemon_path':str(SOURCE),'daemon_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'fragments':fs,'branch_edges':edges,'pointer_records':ptr,'allocation_bank':bank,'original_fixup_checks':verify_original_fixups({int(q['slot'],16)for q in ptr}),'prior_recaptures':rec,'verified_source_counts':counts,**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
