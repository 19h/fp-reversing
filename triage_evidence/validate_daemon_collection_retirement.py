#!/usr/bin/env python3
"""Source-only SSA/SMT collection-retirement and status/output certificate."""
import copy,json,subprocess
from recover_daemon_collection_retirement import ROOT,P,SCOPE,FLAGS,IMAGE,CS,FIXUPS,TABLE,BLOCKS,EDGES,CALLS,sha,h,build,retained
from validate_daemon_constructor_inputs import SSA,bv,split
DECL=''.join('(declare-fun '+n+' () (_ BitVec 64))\n'for n in ['K','C','CELL','N','NEXT','B','O','PTR','OUT','RESULT','CONT','TABLE','FN','STATUS','L','R','P0','P1']+['Z'+str(j)for j in range(31)])+''.join('(declare-fun '+n+' () (_ BitVec 32))\n'for n in ['RAW','IX','MARKER','C0','C1'])+'(declare-fun LB () (_ BitVec 8))\n(declare-fun RB () (_ BitVec 8))\n'
CONST={0:0xffff4abe,1:0xffff9e8f,2:0x614b,3:0xffff9eab,4:0x6ad4,5:0xffffb7af,6:0x10ed8,7:0xd18e9b2b,14:0x50c0,15:0x228e,16:0x8f1,21:0xd18e916e,22:0x0a5cd4cf,23:0x2e71b5ff,27:0xa6}
def z(e):return'((_ zero_extend 32) '+e+')'
def neq(a,b):return'(distinct '+a+' '+b+')'
def mismatch(tt):return'(assert (or '+' '.join(tt)+'))'
def at(ix):return f'(bvadd TABLE {bv(ix*8)})'
def make(s,n,a=None,end=None,r=None,loads=None,ns=None):
 a=BLOCKS[n]if a is None else a;end=int(s['fragments'][n]['instructions'][-1]['ea'],16)if end is None else end;ns=ns or n+'_';ii=[i for i in s['fragments'][n]['instructions']if a<=int(i['ea'],16)<end];ll=dict(loads or{});dd=[]
 for i in ii:
  if i['mnemonic']in('ldr','ldrb','ldrh','ldrsh')and i['ea']not in ll:
   bits=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']in('ldrh','ldrsh')else 32 if i['operands'].startswith('w')else 64;v=ns+'L'+str(len(dd));dd.append('(declare-fun '+v+' () (_ BitVec '+str(bits)+'))');ll[i['ea']]=(v,bits)
 rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K';rr.update(r or{});g=SSA(rr,ll,namespace=ns).run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';return g
def prefix(*gs):return''.join(g.declarations+g.prefix()for g in gs)
def read(g,pc):return next(x for x in g.reads if x['site']==hex(pc))
def addr(g,pc):return read(g,pc)['address']
def target(g,pc,c,a,b):return neq(addr(g,pc),f'(ite {c} {at(a)} {at(b)})')
def solve(n,body,scope):
 q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+body+'\n(check-sat)\n';v=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()=='unsat',(n,v.stdout,v.stderr)
 return{'name':n,'query':q,'result':'unsat','scope':scope}
def verify(s):
 assert s['static_scope']==SCOPE and s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for f in s['fragments'].values():
  a=int(f['start'],16);bb=bytes.fromhex(f['bytes']);assert IMAGE.read(a,len(bb))==bb and h(bb)==f['sha256']and f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(bb,a)]
 for row in s['pointer_records']:assert FIXUPS[int(row['slot'],16)]==row['fixup']and IMAGE.read(int(row['slot'],16),8).hex()==row['raw_bytes']
 assert len(s['branch_edges'])==len(EDGES)
 for e in s['branch_edges']:
  ii=s['fragments'][e['fragment']]['instructions'];assert e['modifier_u16']==int(ii[-2]['operands'].split('#')[1],0)and[int(r['index'],16)for r in e['selected_slots']]==EDGES[e['fragment']]
 for b,ref in zip(s['retirement_banks'],CALLS):
  role,pc,l,r,key,add,lf,rf=ref;assert b['role']==role and b['call_site']==hex(pc)and b['left']==hex(l)and b['right']==hex(r)and b['key_u8']==key and b['additive_u32']==add and b['left_frame_slot']==hex(lf)and b['right_frame_slot']==hex(rf)
  lb,rb=bytes.fromhex(b['left_bytes']),bytes.fromhex(b['right_bytes']);assert lb==IMAGE.read(l,256)and rb==IMAGE.read(r,256);vv=[i^rb[lb[i]^key]for i in range(256)];assert vv==b['results_256']and set(vv)=={0xcc08-add}and b['target']=='libSystem/_free'and b['slot']=='0x10109ff30'
 assert s['free_binding']['symbol']=='_free'and s['free_binding']['total_addend']==0
 for row in s['liveness_intervals']:assert not{p+str(j)for j in row['preserved_registers']for p in('x','w')}&set(row['written_registers'])
 assert s['retained_profiles']==retained()and all(not p['native_evidence']for p in s['retained_profiles'])
 return True

def proofs(s):
 pp=[];tr={}
 def add(n,gs,tt,scope,extra=''):
  gs=gs if isinstance(gs,list)else[gs];pp.append(solve(n,prefix(*gs)+extra+mismatch(tt),scope));tr[n]=[g.record()for g in gs]
 def store(g,k,off,val,base='K'):
  st=g.stores[k];return[neq(st['address'],f'(bvadd {base} {bv(off)})'),neq(st['value'],val)]
 def constants(g,skip=()):return[neq(g.get('w'+str(j)),bv(v,32))for j,v in CONST.items()if j not in skip]
 cr={j:bv(v)for j,v in CONST.items()}
 g=make(s,'drain_setup',r={24:bv(0x6cf4),8:z('IX'),19:'CELL'},loads={'0x1006e3d5c':('TABLE',64),'0x1006e3d70':(bv(0x6cf4),64)})
 add('drain_setup_exact_private_constant_interface',g,constants(g)+[neq(g.get('w9'),'#x0000bdb4'),neq(addr(g,0x1006e3d60),at(0x8f82)),neq(g.get('x19'),'CELL'),neq(g.get('w8'),'IX')],'Selected W24/core phase6cf4; exact custom constants, continuation selector and pointer-cell operand. This call interface overwrites X6; caller status needs its own save.')
 g=make(s,'drain_entry',r={**cr,8:z('IX'),9:bv(0xbdb4),19:'CELL'},loads={'0x1005134f0':('TABLE',64),'0x1005134f4':('CONT',64)})
 add('drain_cell_guard_and_saved_continuation',g,store(g,0,0x43c0,'CONT')+[neq(addr(g,0x1005134f4),f'(bvadd TABLE (bvshl ((_ sign_extend 32) IX) {bv(3)}))'),target(g,0x100513510,'(= CELL #x0000000000000000)',0xbdb7,0xbdb4),neq(g.get('w10'),'#x0000b545'),neq(g.get('x8'),'CONT'),neq(g.get('w3'),'#xffff9eab'),neq(g.get('w4'),'#x00006ad4')],'CELL==0 returns without dereferencing CELL, after table/continuation access. Continuation validity and original frame epoch are premises.')
 g=make(s,'drain_container',r={**cr,10:bv(0xb545),19:'CELL'},loads={'0x1005b6120':('C',64),'0x1005b6140':('TABLE',64)})
 add('drain_container_pointer_read_and_null_partition',g,[neq(addr(g,0x1005b6120),'CELL'),neq(g.get('w9'),'#x00006452'),target(g,0x1005b6144,'(= C #x0000000000000000)',0xb57d,0xb545)],'Readable CELL contains C; null C returns without freeing or writing the already-null cell. Nonnull C reaches head read.')
 g=make(s,'drain_head',r={**cr,9:bv(0x6452),19:'CELL',20:'C'},loads={'0x1005cbf24':('N',64),'0x1005cbf48':('TABLE',64)})
 add('drain_head_read_and_empty_container_route',g,store(g,0,0x9b8,'#x0000614b')+[neq(addr(g,0x1005cbf24),'C'),neq(g.get('w26'),'#x00006e13'),neq(g.get('w24'),'#x0000b57d'),target(g,0x1005cbf4c,'(= N #x0000000000000000)',0x6452,0x645c)],'C.head is read at+0. Empty container is still retired; no tail or payload extent is read by this stage.')
 g=make(s,'drain_node',r={**cr,21:'N',26:bv(0x6e13)},loads={'0x100525104':('NEXT',64),'0x100525108':('B',64),'0x100525124':('TABLE',64)})
 add('drain_next_and_buffer_before_retirement',g,[neq(addr(g,0x100525104),'N'),neq(addr(g,0x100525108),'(bvadd N #x0000000000000018)'),neq(g.get('x25'),'NEXT'),neq(g.get('w28'),'#x00006452'),target(g,0x100525128,'(distinct B #x0000000000000000)',0x6e20,0x6e13)],'Save full next pointer before any allocator call. Null buffer skips only buffer retirement; valid node ownership is required before both reads.')
 # Every allocator family is certified from its actual controller and byte addresses.
 families=[('drain_buffer',0x1007cf698,0x1007cf700,{'0x1007cf6b0':('P0',64),'0x1007cf6b4':('C0',32),'0x1007cf6b8':('P1',64),'0x1007cf6bc':('C1',32),'0x1007cf6cc':('L',64),'0x1007cf6e0':('R',64),'0x1007cf6d4':('LB',8),'0x1007cf6e4':('RB',8),'0x1007cf6f4':('TABLE',64)},0x1007cf6d4,0x1007cf6e4,0x1007cf6f8,0xe4,0x5d,'sub','B',0x9b0,0x9a8),('drain_free_node',0x1005faf58,0x1005fafc4,{'0x1005faf70':('P0',64),'0x1005faf74':('C0',32),'0x1005faf78':('P1',64),'0x1005faf7c':('C1',32),'0x1005faf8c':('L',64),'0x1005fafa0':('R',64),'0x1005faf94':('LB',8),'0x1005fafa4':('RB',8),'0x1005fafb4':('TABLE',64)},0x1005faf94,0x1005fafa4,0x1005fafb8,0x9a,0xe5,'xor','N',0x5f0,0x5e0),('drain_free_container',0x1004d7534,0x1004d7588,{'0x1004d7534':('P0',64),'0x1004d7538':('C0',32),'0x1004d753c':('P1',64),'0x1004d7540':('C1',32),'0x1004d7550':('L',64),'0x1004d7564':('R',64),'0x1004d7558':('LB',8),'0x1004d7568':('RB',8),'0x1004d7578':('TABLE',64)},0x1004d7558,0x1004d7568,0x1004d757c,0xf3,0x43,'xor','C',0x9b0,0x9a8),('outer_free',0x10058081c,0x100580884,{'0x10058081c':(bv(0x6cf4),64),'0x100580824':('P0',64),'0x100580828':('C0',32),'0x10058082c':('P1',64),'0x100580830':('C1',32),'0x10058084c':('L',64),'0x100580860':('R',64),'0x100580854':('LB',8),'0x100580864':('RB',8),'0x100580868':('O',64),'0x100580878':('TABLE',64)},0x100580854,0x100580864,0x10058087c,0xbb,0xbb,'add','O',0x968,0x960)]
 pres={}
 for n,a,e,loads,lp,rp,tp,key,delta,op,arg,lf,rf in families:
  rr={**cr,0:'B',19:'CELL',20:'C',21:'N',24:bv(0xb57d),25:'NEXT',26:bv(0x6e13),28:bv(0x6452)}
  g=make(s,n,a,e,rr,loads,n+'_pre_');pres[n]=g;binop={'sub':'(bvsub C1 C0)','xor':'(bvxor C0 C1)','add':'(bvadd C1 C0)'}[op];ctl=f'(bvmul (bvxor {binop} #x000000a6) #x0a5cd4cf)';byte='((_ extract 7 0) '+ctl+')';extra=f'(assert (= RB (bvxor {byte} {bv(delta,8)})))\n'
  tt=[neq(addr(g,lp),'(bvadd L ((_ zero_extend 56) '+byte+'))'),neq(addr(g,rp),f'(bvadd R ((_ zero_extend 56) (bvxor LB {bv(key,8)})))'),neq(addr(g,tp),at(0xcc08)),neq(g.get('x0'),arg),neq(g.get('x17'),bv(0x46a2))]
  leftpc=next(int(k,16)for k,v in loads.items()if v==('L',64));rightpc=next(int(k,16)for k,v in loads.items()if v==('R',64));tt +=[neq(addr(g,leftpc),'(bvadd K '+bv(lf)+')'),neq(addr(g,rightpc),'(bvadd K '+bv(rf)+')')]
  for var,off in [('P0',0x9c8),('P1',0x9c0)]:
   pc0=next(int(k,16)for k,v in loads.items()if v==(var,64));pc1=next(int(k,16)for k,v in loads.items()if v==('C0'if var=='P0'else'C1',32));tt +=[neq(addr(g,pc0),'(bvadd K '+bv(off)+')'),neq(addr(g,pc1),var)]
  tt.append(neq(g.get({'drain_buffer':'x24','drain_free_node':'x23','drain_free_container':'x21','outer_free':'x20'}[n]),'TABLE'))
  if n=='drain_buffer':tt +=[neq(g.get('w28'),'#x00006452'),neq(g.get('x25'),'NEXT')]
  if n=='drain_free_node':tt +=[neq(g.get('w24'),'#x0000b57d'),neq(g.get('w26'),'#x00006e13'),neq(g.get('x25'),'NEXT')]
  if n=='outer_free':tt +=[neq(addr(g,0x100580868),'(bvadd K #x00000000000077b8)'),neq(g.get('w19'),'#x00007b04'),neq(g.get('w22'),'#x00006cf4')]
  add(n+'_exact_free_selector_argument',g,tt,'All controller words. Pinned original bank arrays establish RB=controller_byte XOR delta for all256 byte inputs per family. This proves selected _free slot/argument under actual root premises; hardware PAC and allocator effects are not tested.',extra)
 g=make(s,'drain_buffer',0x1007cf704,None,{21:'N',24:'TABLE',26:bv(0x6e13),25:'NEXT'},ns='buf_post_')
 add('post_buffer_call_clear_and_node_join',g,store(g,0,0x18,bv(0),'N')+[neq(addr(g,0x1007cf708),at(0x6e13)),neq(g.get('x25'),'NEXT')],'After normal free(B) preserving callee-saved registers, source clears N.buf and selects free(N). Buffer-null path reaches the same free(N) without this store.')
 g=make(s,'drain_free_node',0x1005fafc8,None,{23:'TABLE',24:bv(0xb57d),25:'NEXT',26:bv(0x6e13),28:bv(0x6452)},ns='node_post_')
 add('post_node_call_next_or_container_retirement',g,[target(g,0x1005fafe8,'(= NEXT #x0000000000000000)',0x6452,0x645c),neq(g.get('x21'),'NEXT')],'After normal free(N), the saved NEXT becomes the next node. A finite acyclic list and distinct valid owners are termination/retirement premises.')
 g=make(s,'drain_free_container',0x1004d758c,None,{19:'CELL',20:'C',21:'TABLE',24:bv(0xb57d)},loads={'0x1004d7590':('CONT',64),'0x1004d75ac':('#x0000614b',32)},ns='container_post_')
 add('post_container_call_clear_cell_restore_constants',g,store(g,0,0,bv(0),'CELL')+constants(g,skip=(22,27))+[neq(addr(g,0x1004d7590),'(bvadd K #x00000000000043c0)'),neq(addr(g,0x1004d7594),at(0xb57d)),neq(addr(g,0x1004d75ac),'(bvadd K #x00000000000009b8)'),neq(g.get('x8'),'CONT')],'After normal free(C), clear the supplied CELL and reload CONT. Source re-stages custom caller constants, including W3/W4/W14/W15 needed by the two-child wrapper. No original X6 preservation is promised.')
 g=make(s,'drain_return',r={8:'CONT'})
 add('drain_saved_continuation_transfer',g,[neq(g.get('x8'),'CONT'),neq(g.get('x17'),bv(0xe0d4))],'Static saved-return operand/key diversity only; four table examples are checked separately and no hardware authentication is performed.')
 g=make(s,'outer_finish',r={21:bv(0x6cf4),6:'STATUS'},loads={'0x10090a438':('PTR',64),'0x10090a458':('TABLE',64)})
 add('outer_finish_success_or_disposal_and_status_snapshot',g,store(g,0,0x3c64,'((_ extract 31 0) STATUS)')+[target(g,0x10090a45c,'(= ((_ extract 31 0) STATUS) #x8b3dc651)',0x785b,0x7863),neq(g.get('w9'),'#x00006f33'),neq(g.get('w10'),'#x8b3dc651'),neq(g.get('w11'),'#x69e4bfbf'),neq(g.get('x8'),'PTR'),neq(addr(g,0x10090a438),'(bvadd K #x0000000000003950)')],'This is a common finish, not an error-only routine. Low32 success publishes the supplied pointer; other statuses enter disposal. The saved status is4 B.')
 g=make(s,'outer_dispose',r={11:bv(0x69e4bfbf),8:'PTR'},loads={'0x10097a0f4':('TABLE',64)})
 add('outer_disposal_saved_cell_and_private_marker',g,store(g,0,0x6520,'PTR')+store(g,1,0x4a68,'(bvadd K #x0000000000006520)')+store(g,2,0x36c4,'#x8f8d9650')+[neq(g.get('w22'),'#x00006cf4'),neq(addr(g,0x10097a0f8),at(0x1fbb))],'Failure-side source setup; raw private marker8f8d9650 has no assigned public name or native meaning.')
 g=make(s,'outer_cell',r={8:'PTR',22:bv(0x6cf4)},loads={'0x100732300':('TABLE',64)})
 add('outer_pointer_cell_guard',g,store(g,0,0x5120,'PTR')+[target(g,0x100732304,'(distinct PTR #x0000000000000000)',0x5096,0x5086),neq(g.get('w9'),'#x00006e42')],'NULL supplied pointer-cell address skips its read; nonnull address must be readable before object guard.')
 g=make(s,'outer_value',r={8:'PTR',9:bv(0x6e42)},loads={'0x1007778fc':('O',64),'0x10077791c':('TABLE',64)})
 add('outer_object_guard_and_saved_object',g,store(g,0,0x77b8,'O')+[neq(addr(g,0x1007778fc),'PTR'),target(g,0x100777920,'(= O #x0000000000000000)',0x6e4a,0x6e42),neq(g.get('w22'),'#x00006cf4')],'The object at *PTR is independently guarded. This source view does not establish how PTR aliases an earlier descriptor caller or native object graph.')
 g=make(s,'nested_entry',r={22:bv(0x6cf4),10:'O'},loads={'0x10083dd88':('TABLE',64)})
 add('outer_second_child_cell_to_drain',g,[neq(g.get('x19'),'(bvadd O #x0000000000000008)'),neq(g.get('w24'),'#x00006cf4'),neq(g.get('w8'),'#x00000b68'),neq(addr(g,0x10083dd8c),at(0x3ad1))],'First drain of the outer object supplies CELL=O+8 and return selectorb68. Ownership/layout compatibility is conditional, not inferred from descriptor field resemblance.')
 g=make(s,'nested_return',r={3:bv(CONST[3]),4:bv(CONST[4])},loads={'0x1004c61ec':('O',64),'0x1004c61f0':(bv(0x6cf4),64),'0x1004c61fc':('TABLE',64)})
 add('outer_first_child_cell_after_nested_drain',g,[neq(addr(g,0x1004c61ec),'(bvadd K #x00000000000077b8)'),neq(g.get('x19'),'O'),neq(g.get('w8'),'#x00000b9f'),neq(addr(g,0x1004c6200),at(0x614b))],'Normal child return re-stages W3/W4; wrapper then supplies CELL=O, distinct from prior CELL=O+8.')
 g=make(s,'second_entry',r={14:bv(0x50c0),15:bv(0x228e),8:bv(0xb9f),19:'O'},loads={'0x10058bca4':(bv(0x6cf4),64),'0x10058bcb0':('TABLE',64)})
 add('second_child_reuses_drain_constant_interface',g,[neq(g.get('w9'),'#x0000bdb4'),neq(g.get('w8'),'#x00000b9f'),neq(g.get('x19'),'O'),neq(addr(g,0x10058bcb4),at(0x8f82))],'Source rejoins drain entry with return selectorb9f; remaining custom constants are supplied by the proven child exit/initial paths and normal-call premises.')
 g=make(s,'outer_free',0x100580888,None,{19:bv(0x7b04),20:'TABLE'},loads={'0x100580888':('PTR',64)},ns='outer_free_post_')
 add('post_outer_object_call_clear_partition',g,[neq(addr(g,0x100580888),'(bvadd K #x0000000000005120)'),target(g,0x1005808a0,'(= PTR #x0000000000000000)',0x7b10,0x7b04)],'After normal free(O), nonnull PTR is cleared next; NULL PTR skips that write. Reaching this call through object guard implies PTR!=0 under stable disjoint ownership.')
 g=make(s,'outer_clear',r={8:'PTR'},loads={'0x100543b98':(bv(0x6cf4),64),'0x100543ba4':('TABLE',64)})
 add('outer_pointer_cell_zero_after_object_retirement',g,store(g,0,0,bv(0),'PTR')+[neq(addr(g,0x100543ba8),at(0x310f))],'Explicit *PTR=0 after two normally completed child drains and normal free(O); NULL guard skips this store.')
 g=make(s,'outer_marker',r={22:bv(0x6cf4)},loads={'0x1004ee73c':('MARKER',32),'0x1004ee740':('TABLE',64)})
 add('outer_private_marker_reload',g,[neq(addr(g,0x1004ee73c),'(bvadd K #x00000000000036c4)'),neq(g.get('w8'),'MARKER'),neq(addr(g,0x1004ee744),at(0xaee2))],'All raw markers; failure setup and no intervening alias write supply the particular marker8f8d9650.')
 g=make(s,'outer_class',r={22:bv(0x6cf4),8:z('MARKER')},loads={'0x100708f38':('TABLE',64)})
 add('outer_marker_signed_partition',g,[target(g,0x100708f3c,'(bvsge MARKER #x8f8d9654)',0x5452,0x542a),neq(g.get('w9'),'#x0000486e'),neq(g.get('w10'),'#x0000c378')],'All u32 markers; signed classification is explicit. Only the setup marker is composed through the following default leaf.')
 g=make(s,'outer_low',r={9:bv(0x486e),8:z('MARKER')},loads={'0x10075a4b0':('TABLE',64)})
 add('outer_marker_low_partition',g,[target(g,0x10075a4b4,'(bvslt MARKER #x8f8d9651)',0x48bf,0x486e),neq(g.get('w10'),'#x0000c513')],'All markers at this selected phase; marker8f8d9650 reaches the exact-marker stage.')
 g=make(s,'outer_exact',r={9:bv(0x486e),8:z('MARKER')},loads={'0x1007068d4':('TABLE',64)})
 add('outer_marker_exact_nil_leaf',g,[target(g,0x1007068d8,'(= MARKER #x8f8d9650)',0x8693,0x6924),neq(g.get('w22'),'#x00006cf4'),neq(g.get('w11'),'#x000061be')],'All markers at the captured exact stage; the failure setup marker reaches nil-output preparation. Alternate marker workflows are not claimed complete.')
 g=make(s,'outer_nil',r={11:bv(0x61be)},loads={'0x10078cd18':('RAW',32),'0x10078cd1c':('TABLE',64)})
 add('outer_nil_result_and_u32_status_reload',g,store(g,0,0x3950,bv(0))+[neq(g.get('x8'),bv(0)),neq(g.get('w10'),'RAW'),neq(g.get('x10'),z('RAW')),neq(addr(g,0x10078cd18),'(bvadd K #x0000000000003c64)'),neq(g.get('w9'),'#x00006f33'),neq(addr(g,0x10078cd20),at(0x61be))],'The saved pointer scratch is cleared and status is reloaded as u32. Original high32 X6 bits are not preserved by this outer failure interface.')
 g=make(s,'outer_output',r={8:'RESULT',9:bv(0x6f33),10:z('RAW')},loads={'0x100966d9c':('OUT',64),'0x100966da8':('CONT',64),'0x100966dac':('TABLE',64)})
 add('outer_output_cell_and_zero_extended_status',g,store(g,0,0,'RESULT','OUT')+[neq(addr(g,0x100966d9c),'(bvadd K #x0000000000007700)'),neq(addr(g,0x100966da8),'(bvadd K #x00000000000086d8)'),neq(addr(g,0x100966db0),at(0x6f33)),neq(g.get('x6'),z('RAW')),neq(g.get('x20'),'CONT')],'Shared output stage: RESULT=PTR/raw success on success; RESULT=0/restored low32 status after disposal. OUT must be writable. Actual saved continuation and public ABI remain unknown.')
 g=make(s,'outer_return',r={20:'CONT',6:z('RAW')})
 add('outer_saved_return_transfer',g,[neq(g.get('x20'),'CONT'),neq(g.get('x6'),z('RAW')),neq(g.get('x17'),bv(0x2cca))],'Final authenticated-transfer operands only; full private path returns zero-extended u32 status to saved CONT, not an established public C ABI.')
 g=make(s,'generic_error',r={8:bv(0xb9e),6:'STATUS'},loads={'0x1008f046c':('C',64),'0x1008f0474':('TABLE',64)})
 add('generic_error_status_snapshot_and_collection_cell',g,store(g,0,0x850c,'((_ extract 31 0) STATUS)')+store(g,1,0x1548,'C')+[neq(g.get('x19'),'(bvadd K #x0000000000001548)'),neq(g.get('w24'),'#x00006cf4'),neq(g.get('w8'),'#x00000b9e'),neq(addr(g,0x1008f0480),at(0x3ad1))],'Separate generic constructor error path copies C to a local pointer cell for drain and saves only low32 status; no retained profile takes this caller.')
 g=make(s,'generic_after',loads={'0x1005271b4':(bv(0x6cf4),64),'0x1005271c4':('RAW',32),'0x1005271c8':('TABLE',64)})
 add('generic_after_drain_clear_alias_and_restore_u32',g,store(g,0,0x2ff8,bv(0))+[neq(addr(g,0x1005271c4),'(bvadd K #x000000000000850c)'),neq(g.get('x6'),z('RAW')),neq(g.get('x8'),bv(0x6cf4)),neq(addr(g,0x1005271cc),at(0x3b30))],'Normal generic error drain return clears original saved C and restores only its saved u32 marker, irrespective of drain X6 scratch.')
 g=make(s,'generic_output',r={8:bv(0x6cf4),6:z('RAW')},loads={'0x100758ae8':('RESULT',64),'0x100758aec':('OUT',64),'0x100758b18':('TABLE',64)})
 add('generic_shared_output_and_return_join',g,store(g,0,0,'RESULT','OUT')+[neq(addr(g,0x100758ae8),'(bvadd K #x0000000000002ff8)'),neq(addr(g,0x100758aec),'(bvadd K #x0000000000007068)'),neq(addr(g,0x100758b1c),at(0x188e)),neq(g.get('x6'),z('RAW'))],'This output block is shared with success. Under the proven generic error clear, RESULT=0; positive frozen occurrence alone does not exercise that error path.')
 g=make(s,'generic_return',r={6:z('RAW')},loads={'0x1008c8b80':('CONT',64)})
 add('generic_saved_return_transfer',g,[neq(addr(g,0x1008c8b80),'(bvadd K #x0000000000005ff0)'),neq(g.get('x8'),'CONT'),neq(g.get('x17'),bv(0xfc72)),neq(g.get('x6'),z('RAW'))],'Exact saved generic continuation/source status operands; no public response or native endpoint identity is established.')
 g=make(s,'observed_caller',r={8:bv(0xb70),6:'STATUS'},loads={'0x100902534':('TABLE',64)})
 add('frozen_drain_caller_frame_cell_interface',g,store(g,0,0x6c88,'((_ extract 31 0) STATUS)')+[neq(g.get('x19'),'(bvadd K #x0000000000001c10)'),neq(g.get('w24'),'#x00006cf4'),neq(g.get('w8'),'#x00000b70'),neq(addr(g,0x100902538),at(0x3ad1))],'Actual retained drain caller uses a distinct frame pointer cell and return selectorb70. Its native upstream owner production remains unknown.')
 g=make(s,'observed_after',loads={'0x10081bf94':(bv(0x6cf4),64),'0x10081bfc0':('B',64),'0x10081bfe4':('TABLE',64)})
 add('observed_drain_return_external_frontiers',g,[neq(addr(g,0x10081bfc0),'(bvadd K #x0000000000005490)'),target(g,0x10081bfe8,'(= B #x0000000000000000)',0xc74e,0xc701)],'The retained drain returns here and tests a separate saved pointer. This frontier does not establish the entire subsequent caller cleanup or status restoration.')
 return pp,tr

def alterations(s):
 ops=[('source_byte',lambda t:t['fragments']['drain_node'].__setitem__('bytes','00'+t['fragments']['drain_node']['bytes'][2:])),('pointer_target',lambda t:t['pointer_records'][0]['fixup'].__setitem__('target',0)),('branch_modifier',lambda t:t['branch_edges'][0].__setitem__('modifier_u16',0)),('bank_result',lambda t:t['retirement_banks'][0]['results_256'].__setitem__(0,0)),('bank_frame_slot',lambda t:t['retirement_banks'][3].__setitem__('left_frame_slot','0x5f0')),('binding_symbol',lambda t:t['free_binding'].__setitem__('symbol','_malloc')),('next_liveness',lambda t:t['liveness_intervals'][0]['written_registers'].append('x25')),('frozen_failure_relabel',lambda t:t['retained_profiles'][0]['counts'].__setitem__('outer_dispose',1)),('frozen_unknown_bytes',lambda t:t['retained_profiles'][0]['private_free_calls'][1].__setitem__('known_byte_mask','00'*32)),('native_relabel',lambda t:t['retained_profiles'][0].__setitem__('native_evidence',True))]
 aa=[]
 for n,op in ops:
  t=copy.deepcopy(s);op(t)
  try:verify(t)
  except AssertionError:aa.append({'name':n,'rejected':True})
  else:raise AssertionError(n)
 return aa

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build()and verify(s);pp,tr=proofs(s);aa=alterations(s);sites=[pc for gs in tr.values()for g in gs for pc in g['source_sites']];expected=[i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']not in('braa','blraa')];assert sorted(sites)==sorted(expected)and len(sites)==len(set(sites))
 counts={**s['verified_source_counts'],'component_queries_unsat':len(pp),'translated_instruction_instances':len(sites),'SSA_definitions':sum(g['SSA_definitions']for gs in tr.values()for g in gs),'rejected_alterations':len(aa),'allocator_calls_metadata_checked':len(CALLS)}
 c={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_constructor_inputs.py':sha(ROOT/'validate_daemon_constructor_inputs.py')},'source_recapture_match':True,'proofs':pp,'translations':tr,'alterations':aa,'all_nonbranch_noncall_instructions_covered_once':True,'verified_counts':counts,'static_scope':SCOPE,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
