#!/usr/bin/env python3
"""Static source/callback/word-width certificate; no new target execution."""
import copy,json,subprocess
from recover_daemon_scalar_field_population import ROOT,P,SCOPE,FLAGS,IMAGE,CS,FIXUPS,TABLE,BLOCKS,PROJECTIONS,sha,h,build,helper_summary,retained
from validate_daemon_constructor_inputs import SSA as ParentSSA,bv,split
class SSA(ParentSSA):
 def run(self,f,end):
  for i in f['instructions']:
   pc=int(i['ea'],16)
   if pc>=end:break
   if i['mnemonic']=='madd':
    p=split(i['operands']);w=32 if p[0].startswith('w')else 64;self.put(p[0],f'(bvadd (bvmul {self.get(p[1],w)} {self.get(p[2],w)}) {self.get(p[3],w)})');self.sites.append(i['ea'])
   else:super().run({'instructions':[i]},pc+4)
  return self
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in ['K','HROOT','C1','CELL','NODE','BUF','CONT','TABLE','FN','STATUS','GEN64','INTERNAL','CTX_CELL','CTX','P0','P1','L','R','ARG']+['Z'+str(j)for j in range(31)])+''.join('(declare-fun '+n+' () (_ BitVec 32))\n'for n in ['HE','SIZE','CTR0','CTR1','COUNTER'])+'(declare-fun LB () (_ BitVec 8))\n(declare-fun RB () (_ BitVec 8))\n'
def z(e):return'((_ zero_extend 32) '+e+')'
def low(e):return'((_ extract 31 0) '+e+')'
def neq(a,b):return'(distinct '+a+' '+b+')'
def mismatch(tt):return'(assert (or '+' '.join(tt)+'))'
def frame(off):return'(bvadd K '+bv(off)+')'
def hf(off):return'(bvadd (bvsub K #x00000000000000c0) '+bv(off)+')'
def at(ix):return'(bvadd TABLE '+bv(ix*8)+')'
def make(s,n,a=None,end=None,r=None,loads=None,ns=None):
 a=int(s['fragments'][n]['start'],16)if a is None else a
 if end is None:end=int(s['fragments'][n].get('end',s['fragments'][n]['instructions'][-1]['ea']),16);end=int(s['fragments'][n]['instructions'][-1]['ea'],16)if s['fragments'][n]['instructions'][-1]['mnemonic']=='braa'else end
 ns=ns or n+'_';ii=[i for i in s['fragments'][n]['instructions']if a<=int(i['ea'],16)<end];ll=dict(loads or{});dd=[]
 for i in ii:
  if i['mnemonic']in('ldr','ldrb')and i['ea']not in ll:
   bits=8 if i['mnemonic']=='ldrb'else 32 if i['operands'].startswith('w')else 64;v=ns+'L'+str(len(dd));dd.append('(declare-fun '+v+' () (_ BitVec '+str(bits)+'))');ll[i['ea']]=(v,bits)
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=SSA(rr,ll,namespace=ns).run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';return g
def prefix(*gs):return''.join(g.declarations+g.prefix()for g in gs)
def read(g,pc):return next(x for x in g.reads if x['site']==hex(pc))
def addr(g,pc):return read(g,pc)['address']
def target(g,pc,c,a,b):return neq(addr(g,pc),f'(ite {c} {at(a)} {at(b)})')
def solve(n,body,scope,arrays=False):
 q='(set-option :timeout 15000)\n(set-logic '+('QF_ABV'if arrays else'QF_BV')+')\n'+DECL+body+'\n(check-sat)\n';v=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()=='unsat',(n,v.stdout,v.stderr)
 return{'name':n,'query':q,'result':'unsat','scope':scope}
def verify(s):
 assert s['static_scope']==SCOPE and s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for f in s['fragments'].values():
  a=int(f['start'],16);bb=bytes.fromhex(f['bytes']);assert IMAGE.read(a,len(bb))==bb and h(bb)==f['sha256']and f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(bb,a)]
 for r in s['pointer_records']:assert IMAGE.read(int(r['slot'],16),8).hex()==r['raw_bytes']and FIXUPS[int(r['slot'],16)]==r['fixup']
 assert s['helper_complete']==helper_summary()and s['retained_profiles']==retained()
 b=s['helper_call_bank'];l,r=bytes.fromhex(b['left_bytes']),bytes.fromhex(b['right_bytes']);assert l==IMAGE.read(0x100e99700,256)and r==IMAGE.read(0x100f4e190,256);assert [i^r[l[i]^0x81]for i in range(256)]==b['results_256']and set(b['results_256'])=={0x48}and b['target']=='0x100444dfc'and b['modifier_u16']==0x9a7c
 k=s['read_only_IDA_knowledge_snapshot'];assert k['database_id']=='6b117c693e3b'and not k['source_semantic_claims_taken_from_knowledge']and[k['queries'][j]['result']['count']for j in range(3)]==[0,4,0]
 assert all(x['scope']=='global'and x['verification']=='unverified'for x in k['queries'][1]['result']['facts'])
 return True

def proofs(s):
 pp=[];tr={}
 def add(n,g,tt,scope,extra='',deps=()):
  gg=g if isinstance(g,list)else[g];pp.append(solve(n,prefix(*deps,*gg)+extra+mismatch(tt),scope));tr[n]=[x.record()for x in gg]
 def store(g,j,a,v):return[neq(g.stores[j]['address'],a),neq(g.stores[j]['value'],v)]
 call=make(s,'caller',r={22:bv(0x6cf4),19:'HROOT'},loads={'0x1009ab12c':('TABLE',64)})
 add('builder_C1_keyed_lookup_argument_interface',call,[neq(call.get('x8'),'(bvadd HROOT #x0000000000000008)'),neq(call.get('w9'),'#x7dab886f'),neq(call.get('w10'),'#x00000922'),neq(call.get('x11'),frame(0x601c)),neq(addr(call,0x1009ab130),at(0x3b01))],'Selected core phase6cf4; pointer-cell,encoded identifier,borrowed value output and saved return selector. This precedes serialization; application meaning of the identifier is unknown.')
 ent=make(s,'entry',r={8:call.get('x8'),9:call.get('x9'),10:call.get('x10'),11:call.get('x11'),22:bv(0x6cf4)},loads={'0x10084799c':('C1',64),'0x1008479a0':('TABLE',64),'0x1008479a4':('CONT',64)})
 assert len(ent.stores)==5
 add('accessor_snapshot_cursor_and_collection_guard',ent,[neq(addr(ent,0x10084799c),'(bvadd HROOT #x0000000000000008)'),neq(addr(ent,0x1008479a4),at(0x922))]+store(ent,0,frame(0x7af0),'CONT')+store(ent,1,frame(0x4ca0),frame(0x601c))+store(ent,2,frame(0x59b0),bv(0))+store(ent,3,frame(0x84cc),'#x8b3dc651')+store(ent,4,frame(0x8048),'#x797188010b5fa78c')+[target(ent,0x1008479f4,'(distinct C1 #x0000000000000000)',0x3d4f,0x3cc0),neq(ent.get('w6'),'#x74c29d88'),neq(ent.get('w9'),'#x7dab886f')],'Actual caller register outputs compose into entry. Null collection returns invalid marker; entry stores the output address,not an output value. Stable frame/child ownership remain premises.',deps=(call,))
 g=make(s,'lookup_call',r={22:bv(0x6cf4),8:'C1',9:z('HE')},loads={'0x10074ab90':('TABLE',64)})
 add('existing_lookup_node_cell_and_return_interface',g,[neq(g.get('x8'),'C1'),neq(g.get('w9'),'HE'),neq(g.get('w10'),'#x0000130c'),neq(g.get('x11'),frame(0x59b0)),neq(addr(g,0x10074ab94),at(0x18e2))],'Reuses the earlier first-match lookup contract with NODE output cell frame+59b0 and return130c. Source preserves the requested identifier into lookup.')
 status=make(s,'lookup_status',r={6:'STATUS'},loads={'0x1004e9b70':(bv(0x6cf4),64),'0x1004e9ba0':('TABLE',64)})
 add('lookup_success_enters_record_reader_other_statuses_relay',status,[target(status,0x1004e9ba4,'(= '+low('STATUS')+' #x8b3dc651)',0x9aa9,0x3cc0),neq(status.get('w8'),'#x00007023'),neq(status.get('x6'),'STATUS')],'All raw X6 words; exact low32 success enters found-node handling. The prior lookup miss74c29ded and every other non-success relay unchanged from this stage.')
 g=make(s,'return',r={6:'STATUS'},loads={'0x1006f76a8':('CONT',64)})
 add('accessor_saved_return_and_raw_status',g,[neq(addr(g,0x1006f76a8),frame(0x7af0)),neq(g.get('x8'),'CONT'),neq(g.get('x6'),'STATUS'),neq(g.get('x17'),bv(0x90ec))],'Saved continuation922 targets the builder caller. No value-output store exists in this relay.')
 g=make(s,'found_node',r={8:bv(0x7023)},loads={'0x1009238e4':('NODE',64),'0x1009238e8':('BUF',64),'0x1009238ec':('SIZE',32),'0x10092390c':('TABLE',64)})
 add('found_node_buffer_extent_and_null_guard',g,[neq(addr(g,0x1009238e4),frame(0x59b0)),neq(addr(g,0x1009238e8),'(bvadd NODE #x0000000000000018)'),neq(addr(g,0x1009238ec),'(bvadd NODE #x0000000000000010)')]+store(g,0,frame(0x3710),'BUF')+[target(g,0x100923910,'(= BUF #x0000000000000000)',0x7067,0x7023),neq(g.get('w9'),'SIZE'),neq(g.get('w6'),'#x74c29d88')],'Found node must be valid before its buffer/extent reads. Null buffer relays invalid marker. Complete native owner validity is not inferred from lookup success.')
 g=make(s,'found_extent',r={8:bv(0x7023),9:z('SIZE')},loads={'0x1005dd9e4':('#x797188010b5fa78c',64),'0x1005dda20':('TABLE',64)})
 add('record_header_extent_gate_and_cursor_snapshot',g,store(g,0,frame(0xa638),z('SIZE'))+store(g,1,frame(0xa640),'#x797188010b5fa78c')+[target(g,0x1005dda24,'(bvugt SIZE #x00000009)',0xc217,0x7067),neq(g.get('w16'),'#x00000074'),neq(g.get('x8'),'#x797188010b5fa78c'),neq(g.get('w6'),'#x74c29d8f')],'All u32 node extents with entry cursor0; exactly SIZE>=10 enters header reading. Buffer ownership and complete existing-value interpretation remain outside this component.')
 g=make(s,'found_header',r={16:bv(0x74),8:bv(0x797188010b5fa78c),1:'BUF'},loads={'0x10074adfc':('TABLE',64)})
 add('found_header_first_word_decoder_interface',g,[neq(g.get('x4'),bv(0x661a590b302baf96)),neq(g.get('w8'),'#x00008c3f'),neq(g.get('w16'),'#x00000074'),neq(g.get('x1'),'BUF'),neq(addr(g,0x10074ae00),at(0x2520))],'Initial header-word decoder key corresponds to offset0; return74 and original preparation2520 are identified. The rest of the found-record/type/value workflow is deliberately left unproved here.')
 callerstat=make(s,'caller_status',r={6:'STATUS'},loads={'0x1006985e4':(bv(0x6cf4),64),'0x100698618':('TABLE',64)})
 add('only_returned_miss_marker_selects_population',callerstat,[target(callerstat,0x10069861c,'(= '+low('STATUS')+' #x74c29ded)',0x89ec,0x1c9),neq(callerstat.get('w20'),'#x000001c9'),neq(callerstat.get('x21'),bv(0x6cf4)),neq(callerstat.get('x6'),'STATUS')],'Every returned status word: only low32 marker74c29ded enters the population block; all other statuses reach common finish. This does not complete the unobserved found-record reader.')
 pop=make(s,'populate',end=0x1006f0b24,r={20:bv(0x1c9)},loads={'0x1006f0abc':('P0',64),'0x1006f0ac0':('CTR0',32),'0x1006f0ac4':('P1',64),'0x1006f0ac8':('CTR1',32),'0x1006f0ae4':('L',64),'0x1006f0af8':('R',64),'0x1006f0aec':('LB',8),'0x1006f0afc':('RB',8),'0x1006f0b10':('TABLE',64)},ns='pop_pre_')
 ctl='(bvmul (bvxor (bvadd CTR0 CTR1) #x000000a6) #x0a5cd4cf)';byte='((_ extract 7 0) '+ctl+')';A=frame(0x10cb8);tag='(bvadd (bvmul (bvxor '+low(A)+' #xdc40790b) #x5973a279) #x0250710d)'
 add('population_staged_word_and_original_helper_call',pop,store(pop,0,A,tag)+[neq(addr(pop,0x1006f0aec),'(bvadd L ((_ zero_extend 56) '+byte+'))'),neq(addr(pop,0x1006f0afc),'(bvadd R ((_ zero_extend 56) (bvxor LB #x81)))'),neq(addr(pop,0x1006f0b14),at(0xcc58)),neq(addr(pop,0x1006f0abc),frame(0x9c8)),neq(addr(pop,0x1006f0ac0),'P0'),neq(addr(pop,0x1006f0ac4),frame(0x9c0)),neq(addr(pop,0x1006f0ac8),'P1'),neq(addr(pop,0x1006f0ae4),frame(0x870)),neq(addr(pop,0x1006f0af8),frame(0x868)),neq(pop.get('x0'),A),neq(pop.get('x22'),frame(0x10000)),neq(pop.get('x19'),'TABLE'),neq(pop.get('w21'),'#x000047f4')],'All controller words;256 original bank cases justify helper target444dfc under E-bank root premises. Staged word is identified without assigning it operation/authorization semantics. Required callee-saved registers and SP must survive the call.','(assert (= RB (bvxor '+byte+' #x48)))\n')
 post=make(s,'populate',0x1006f0b28,None,{19:'TABLE',20:bv(0x1c9),21:bv(0x47f4),22:frame(0x10000)},loads={'0x1006f0b28':(low('GEN64'),32),'0x1006f0b3c':('HROOT',64),'0x1006f0b40':('C1',64)},ns='pop_post_')
 add('helper_low_word_to_C1_scalar_constructor',post,[neq(addr(post,0x1006f0b28),frame(0x10cc0)),neq(addr(post,0x1006f0b3c),frame(0x3950)),neq(addr(post,0x1006f0b40),'(bvadd HROOT #x0000000000000008)'),neq(post.get('x0'),'C1'),neq(post.get('w10'),'(bvxor '+low('GEN64')+' #xdeac5766)'),neq(post.get('w19'),'#x7dab886f'),neq(post.get('w20'),'#x000001c9'),neq(post.get('w21'),'#x000047f4'),neq(addr(post,0x1006f0b4c),at(0x18a5))],'Normal helper return: caller reads only low32 of the64-bit result at ARG+8. Actual source selects C1 at builder+8,not C0; same requested encoded identifier is supplied to the u32 adapter.')
 ad=make(s,'adapter',r={0:post.get('x0'),10:post.get('x10'),19:post.get('x19'),20:post.get('x20'),21:post.get('x21')},loads={'0x100752368':('TABLE',64),'0x10075236c':('CONT',64)})
 # Some table pointer reload sites are modeled independently by make; named CONT
 # is specifically the source-selected saved return pointer.
 add('scalar_adapter_same_value_key_and_outer_return',ad,[neq(ad.get('w8'),'#x00006cf4'),neq(ad.get('x0'),'C1'),neq(ad.get('w19'),'#x7dab886f'),neq(ad.get('w10'),'(bvxor '+low('GEN64')+' #xdeac5766)')]+[neq(ad.stores[0]['address'],frame(0x3598)),neq(ad.stores[0]['value'],'CONT'),neq(addr(ad,0x10075236c),at(0x1c9)),target(ad,0x100752398,'(= C1 #x0000000000000000)',0x47f4,0x482e)],'Source outputs from the population block feed the existing u32 adapter. Borrowed frame/continuation validity and normal constructor semantics remain premises.',deps=(post,))
 root=make(s,'root',r={8:ad.get('x8'),0:ad.get('x0'),19:ad.get('x19'),10:ad.get('x10')},loads={'0x1008282a4':('TABLE',64)})
 add('typed_u32_root_defaults_preserve_generated_operand',root,[neq(root.get('x0'),'C1'),neq(root.get('w19'),'#x7dab886f'),neq(root.get('w10'),'(bvxor '+low('GEN64')+' #xdeac5766)'),neq(root.get('w9'),'#x000086b4'),neq(root.get('w21'),'#x8b3dc655'),neq(root.get('w11'),'#x00000222'),neq(root.get('x20'),bv(0)),neq(addr(root,0x1008282a8),at(0x5eb2))],'Composed adapter/root register epochs: fixed u32 tag and4 B extent, same generated operand/identifier and inner constructor return222. Earlier constructor/lookup/append certificates supply downstream effects.',deps=(post,ad))
 g=make(s,'typed_return',r={6:'STATUS'},loads={'0x100781e0c':('CONT',64),'0x100781e10':(bv(0x6cf4),64)})
 add('typed_constructor_outer_return_and_phase',g,[neq(addr(g,0x100781e0c),frame(0x3598)),neq(g.get('x8'),'CONT'),neq(g.get('x21'),bv(0x6cf4)),neq(g.get('x6'),'STATUS')],'Inner return reloads the outer saved continuation,here table1c9 ->common finish. Actual constructor completion and saved-frame integrity are separate premises.')
 g=make(s,'finish',r={21:bv(0x6cf4),6:'STATUS'},loads={'0x10090a438':('HROOT',64),'0x10090a458':('TABLE',64)})
 add('population_result_common_builder_finish',g,store(g,0,frame(0x3c64),low('STATUS'))+[target(g,0x10090a45c,'(= '+low('STATUS')+' #x8b3dc651)',0x785b,0x7863),neq(g.get('x8'),'HROOT')],'Normal constructor return feeds the already recovered builder success/disposal interface. No public error name or native output transaction is inferred.')
 stack=make(s,'helper_stack',r={0:frame(0x10cb8)})
 expected=[(0x60,'Z28'),(0x68,'Z27'),(0x70,'Z26'),(0x78,'Z25'),(0x80,'Z24'),(0x88,'Z23'),(0x90,'Z22'),(0x98,'Z21'),(0xa0,'Z20'),(0xa8,'Z19'),(0xb0,'Z29'),(0xb8,'Z30'),(0x48,frame(0x10cb8))];assert len(stack.stores)==len(expected)
 tt=[neq(stack.get('sp'),'(bvsub K #x00000000000000c0)')]
 for j,(off,val)in enumerate(expected):tt+=store(stack,j,hf(off),val)
 add('helper_prologue_stack_and_argument_save',stack,tt,'192 B helper frame and exact callee-saved/argument slots. PACIBSP is outside the scalar projection; saved LR is an independent post-PAC value. Unknown computed-memory aliases and native saved-slot integrity are not proved.')
 ctx=make(s,'helper_context',r={'sp':'(bvsub K #x00000000000000c0)'},loads={'0x100447970':('CTX_CELL',64),'0x100447974':('CTX',64)})
 add('helper_context_pointer_reload',ctx,[neq(addr(ctx,0x100447970),hf(0x50)),neq(addr(ctx,0x100447974),'CTX_CELL'),neq(ctx.get('x20'),'CTX')],'Complete-helper write census checks no X20 clobber between this reload and the counter read. Stable pointer-cell ownership remains a premise.')
 ctr=make(s,'helper_counter_read',r={20:ctx.get('x20')},loads={'0x1004486a0':('COUNTER',32)})
 add('helper_u32_context_word_read',ctr,[neq(addr(ctr,0x1004486a0),'(bvadd CTX #x0000000000000034)'),neq(ctr.get('x30'),z('COUNTER'))],'Source reads one u32 at context+34. No W30/X30 writes occur before the tail increment,as checked over the complete helper.',deps=(ctx,))
 emit=make(s,'helper_output',r={'sp':'(bvsub K #x00000000000000c0)',30:ctr.get('x30'),11:'INTERNAL'},loads={'0x10044a394':('CTX_CELL',64),'0x10044a398':('CTX',64),'0x10044a3b8':(frame(0x10cb8),64)})
 assert len(emit.stores)==2
 add('helper_tail_context_update_and_64bit_result_store',emit,store(emit,0,'(bvadd CTX #x0000000000000034)','(bvadd COUNTER #x00000001)')+store(emit,1,frame(0x10cc0),'(bvxor INTERNAL #xc0eaaa2272eb67c0)')+[neq(addr(emit,0x10044a394),hf(0x50)),neq(addr(emit,0x10044a3b8),hf(0x48)),neq(addr(emit,0x10044a398),'CTX_CELL')],'Full64 result at ARG+8 requires at least16 B argument storage. The u32 update is relative to the prior source read,not necessarily the function-entry value. INTERNAL remains opaque; pointer-cell stability/frame and valid state owners are premises.',deps=(ctx,ctr))
 pp.extend(word_joins())
 return pp,tr

def word_joins():
 A=frame(0x10cc0);m='M'
 for j in range(8):m=f'(store {m} (bvadd {A} {bv(j)}) ((_ extract {8*j+7} {8*j}) GEN64))'
 body='(declare-fun M () (Array (_ BitVec 64) (_ BitVec 8)))\n(define-fun W () (Array (_ BitVec 64) (_ BitVec 8)) '+m+')\n';word='(concat '+' '.join(f'(select W (bvadd {A} {bv(j)}))'for j in range(3,-1,-1))+')'
 p0=solve('helper_LE64_store_to_caller_LE32_load',body+mismatch([neq(word,low('GEN64'))]),'All initial byte memories/K/GEN64 values: caller load at the first four bytes of the source64-bit output sees its low32 word. Native lifetime and unmodeled writes remain separate.',True)
 p1=solve('generated_scalar_identifier_payload_and_width_codec',mismatch([neq('(bvxor #x7dab886f #x8b3dc651)','#xf6964e3e'),neq('(bvxor (bvxor '+low('GEN64')+' #xdeac5766) #x8b3dc651)','(bvxor '+low('GEN64')+' #x55919137)'),neq('(bvxor #x8b3dc655 #x8b3dc651)','#x00000004'),neq('(bvxor #x86b4 #x11c3)','#x9777')]),'All64-bit helper output words; preceding source joins plus the existing header/payload codec give wire identifierf6964e3e,tag9777,extent4 and BE32(low32(GEN64) XOR55919137). Upper32 result bits do not enter this scalar field.')
 return[p0,p1]

def alterations(s):
 ops=[('source_byte',lambda t:t['fragments']['populate'].__setitem__('bytes','00'+t['fragments']['populate']['bytes'][2:])),('pointer_target',lambda t:t['pointer_records'][0]['fixup'].__setitem__('target',0)),('helper_width',lambda t:t['helper_complete']['instructions'][-10].__setitem__('mnemonic','strb')),('helper_arg_use',lambda t:t['helper_complete']['initial_X0_uses'].append({'ea':'0x100444e20','mnemonic':'ldr','operands':'w9, [x0]'})),('counter_clobber',lambda t:t['helper_complete']['W30_clobbers_after_counter_read'].append('0x10044a390')),('bank_result',lambda t:t['helper_call_bank']['results_256'].__setitem__(0,0)),('native_relabel',lambda t:t['retained_profiles'][0].__setitem__('native_evidence',True)),('inferred_as_snapshot',lambda t:t['retained_profiles'][0].__setitem__('helper_low32_is_inferred_not_register_snapshot',False)),('wire_field',lambda t:t['retained_profiles'][0]['wire_field'].__setitem__('payload_hex','00000000')),('knowledge_as_proof',lambda t:t['read_only_IDA_knowledge_snapshot'].__setitem__('source_semantic_claims_taken_from_knowledge',True))]
 aa=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t)
  try:verify(t)
  except AssertionError:aa.append({'name':n,'rejected':True})
  else:raise AssertionError(n)
 return aa

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build()and verify(s);pp,tr=proofs(s);aa=alterations(s);sites=[pc for vs in tr.values()for v in vs for pc in v['source_sites']];expected=[i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']not in('braa','blraa')];assert sorted(sites)==sorted(expected)and len(sites)==len(set(sites))
 counts={**s['verified_source_counts'],'component_queries_unsat':len(pp),'translated_instruction_instances':len(sites),'SSA_definitions':sum(v['SSA_definitions']for vs in tr.values()for v in vs),'rejected_alterations':len(aa),'byte_memory_joins':1}
 c={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_constructor_inputs.py':sha(ROOT/'validate_daemon_constructor_inputs.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'alterations':aa,'all_primary_nonbranch_noncall_and_projected_instructions_covered_once':True,'whole_helper_value_semantics_proved':False,'verified_counts':counts,'static_scope':SCOPE,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
