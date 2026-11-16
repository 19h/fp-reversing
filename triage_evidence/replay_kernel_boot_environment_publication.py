#!/usr/bin/env python3
"""Independent byte formulas and fresh CPU replay; no probe imports.
O(visits+journals+mapped bytes) time/space. Private source evidence only.
"""
import struct
from hashlib import sha256
from unicorn import arm64_const as ar
from probe_rpc502_vm_handoff import decode
from replay_kernel_vm_mig import Replay as Core
import recover_kernel_boot_environment_publication as R

P=0x6500000000;SIZE=0x100000;SP=P+0xf0000;INPUT=P+0x4000;HEADER_INPUT=P+0x6000;CPU=0xfffffe000cac7520
LEAVES={0xfffffe000c621194:'declared_vector_registration_no_RAM_effect',0xfffffe000c47cce0:'declared_early_registration_no_RAM_effect'}

def oracle(row,e,parent=None):
 c=row['configuration'];checks=[];before=decode(row['initial_private_RAM']);after=decode(row['final_private_RAM']);wanted={}
 for r in row['initial_image_fixtures']:
  a=int(r['address'],16)
  for j,b in enumerate(bytes.fromhex(r['bytes_hex'])):wanted[a+j]=b
 def get(a,n):return bytes(wanted[a+j] for j in range(n)) if a>=0xffff000000000000 else before[a-P:a-P+n]
 def value(a,n):return int.from_bytes(get(a,n),'little')
 def put(a,b):
  assert all(a+j in wanted for j in range(len(b)))
  for j,x in enumerate(b):wanted[a+j]=x
 def store(a,n,v):put(a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
 def check(name,p):assert p,('environment_contract',name,c['label']);checks.append(name)
 if parent:
  check('exact_predecessor_mutable_image_transfer',[(r['address'],r['bytes_hex']) for r in row['initial_image_fixtures']]==[(r['address'],r['bytes_hex']) for r in parent['final_image_globals']])
 if c.get('main'):
  put(R.ARGS,get(INPUT,1152));put(R.HEADER,get(HEADER_INPUT,856));store(0xfffffe0007ef9168,8,R.ARGS);store(0xfffffe0007f8b5e0,8,R.HEADER)
  store(0xfffffe0007e6d9b8,8,value(R.HEADER+0x198,8));store(0xfffffe0007e6d148,8,value(R.HEADER+0x18,8))
  zeros={2:2,0xd0:8,0x4c:4,0x50:16,0xa8:16,0xc8:4,0xb8:16,0x1c0:8,0x1c8:4,0x1e8:16,0x1e0:8,0x1f8:8,0x88:16,0x98:16,0x78:16,0x180:32,0x1a0:32,0x8f0:8,0x8f8:4,0x900:8}
  for off,n in zeros.items():put(CPU+off,bytes(n))
  for off,n,v in [(0x110,8,0xffffffffffffffff),(0x160,8,0xfffffe000ca8c000),(0x168,8,0),(0x48,4,0x80000000),(0x1dc,4,0x50535553),(0x8e8,4,0xffffffff)]:store(CPU+off,n,v)
  put(CPU+0x200,bytes.fromhex(next(r['bytes_hex'] for r in e['literal_data'] if r['address']==hex(R.LITERAL))))
  argument=R.ARGS;mode=0
  check('actual_main_copy_and_publisher_call_ABI',[(r['PC'],list(map(lambda x:int(x,16),r['arguments3']))) for r in row['original_call_entries'][:2]]==[(hex(R.COPY),[R.ARGS,INPUT,1152]),(hex(R.COPY),[R.HEADER,HEADER_INPUT,856])] and row['original_call_entries'][2]['PC']==hex(R.PLATFORM) and list(map(lambda x:int(x,16),row['original_call_entries'][2]['arguments3'][:2]))==[0,R.ARGS])
  check('only_two_declared_registration_returns',[(m['pc'],m['symbol']) for m in row['API_models']]==[(hex(a),n) for a,n in LEAVES.items()])
 else:argument=c.get('argument',INPUT);mode=c.get('mode',0)&0xffffffff;check('direct_platform_prefix_has_no_callee_output_models',row['API_models']==[])
 initialized=value(R.STATE,4)!=0;new=not initialized
 if new:
  store(0xfffffe0007f8b5e8,4,2);store(R.STATE,4,1);store(R.STATE+0xa0,8,argument)
  store(R.STATE+0x98,8,value(argument+0x60,8));store(R.STATE+0xa8,8,value(argument+0x68,4))
  store(R.STATE+8,8,value(argument+0x28,8));put(R.STATE+0x10,get(argument+0x38,16));store(R.STATE+0x20,8,value(argument+0x48,8))
  packed=value(argument+0x50,8);store(R.STATE+0x28,8,packed&255);store(R.STATE+0x88,1,((packed>>8)+(packed>>24))&3)
  store(R.STATE+0x89,1,value(argument+0x52,1)+1);store(R.STATE+0x30,8,value(argument+0x30,8))
  put(R.STATE+0x38,bytes.fromhex(next(r['bytes_hex'] for r in e['literal_data'] if r['address']==hex(R.PATTERN))))
  check('original_string_helpers_are_executed_for_initial_publication',[r['PC'] for r in row['original_call_entries'][-3:]]==list(map(hex,[R.STRLCPY,R.STRLEN,R.COPY])))
 base=value(R.STATE+0x98,8);extent=value(R.STATE+0xa8,8);carry=base+extent>=1<<64
 if mode==0 and not carry:
  store(R.TREE,8,base);store(R.TREE+8,8,extent);store(R.TREE+16,8,base+extent);store(R.TREE+24,4,int(base!=0))
 expected_boundary=R.NEXT_CONTEXT if mode else 0xfffffe000c5e6afc if carry else R.NEXT_TREE
 check('guard_mode_and_unsigned_carry_select_exact_boundary',row['boundary']['pc']==hex(expected_boundary))
 regs=list(map(lambda x:int(x,16),row['boundary']['registers31']))
 if mode:check('mode_nonzero_restores_frame_and_forwards_context_X0',int(row['boundary']['SP'],16)==SP and regs[0]==argument and all(regs[j]==int(row['entry_registers31'][j],16) for j in range(19,31)))
 else:check('mode_zero_retains_platform_frame_at_helper_boundary',int(row['boundary']['SP'],16)==SP-0x90-(0xc0 if c.get('main') else 0))
 for r in row['final_image_globals']:
  a=int(r['address'],16);check('whole_mutable_region_'+r['address'],bytes.fromhex(r['bytes_hex'])==bytes(wanted[a+j] for j in range(len(bytes.fromhex(r['bytes_hex'])))))
 check('all_private_bytes_outside_explicit_stack_guard_preserved',before[:SP-P-0x1000]==after[:SP-P-0x1000] and before[SP-P+0x100:]==after[SP-P+0x100:])
 if parent:check('reentry_preserves_original_bootargs_pointer',value(R.STATE+0xa0,8)==R.ARGS)
 check('generic_initializer_is_not_executed',not any(r['pc']==hex(R.GENERIC) for r in row['source_visits']))
 return {'checks':checks,'first_publication':new,'mode_low32':hex(mode),'bootargs_pointer':hex(value(R.STATE+0xa0,8)),'tree_base':hex(base),'tree_extent_bytes':extent,'tree_addition_carry':carry,'whole_mutable_bytes_checked':len(wanted),'private_nonstack_bytes_checked':SIZE-0x1100}

class Replay(Core):
 def __init__(self,image,row):
  super().__init__(image,row);self.events=[];self.logical=[]
  for j in range(32):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),0)
 def code(self,u,a,n,d):
  self.finish()
  if a in [R.PLATFORM,R.STRLCPY,R.STRLEN,R.COPY]:self.events.append({'PC':hex(a),'arguments3':[hex(self.reg(j)) for j in range(3)],'return_PC':hex(self.reg(30)),'source_visit_index':self.seq})
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16):
   m=self.models[self.mi];assert a in LEAVES and m['symbol']==LEAVES[a] and m['return_value']=='0x0'
   for j in range(18):assert int(m['after_registers31'][j],16)==(0 if j==0 else (((j+1)*0x123456789abcdef)^((self.mi+1)*0x8b3dc651))&0xffffffffffffffff)
   assert int(m['after_NZCV'],16)==(0xf0000000 if (self.mi+1)&1 else 0)
  if self.seq<len(self.p['source_visits']):
   raw=bytes(u.mem_read(a,4));ins=list(self.image.k.cs.disasm(raw,a))
   if ins and ins[0].mnemonic in ['paciza','xpaci']:
    assert raw==self.image.k.read(a,4) and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()}
    self.logical.append({'PC':hex(a),'kind':ins[0].mnemonic,'source_visit_index':self.seq});self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_address_PAC_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.events==self.p['original_call_entries'] and self.logical==self.p['logical_envelopes']
  assert bytes(self.u.mem_read(P,SIZE))==decode(self.p['final_private_RAM']);self.counts['whole_private_bytes_checked']+=SIZE
  assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}==self.p['final_page_sha256'];self.counts['whole_image_page_bytes_checked']+=len(self.pages)*4096
  for j,x in enumerate(self.p['final_vectors']):assert hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))==x;self.counts['vector_registers_checked']+=1
  self.counts['original_call_entries_checked']+=len(self.events);return dict(self.counts)
