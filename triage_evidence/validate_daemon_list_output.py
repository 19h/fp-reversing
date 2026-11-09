#!/usr/bin/env python3
"""Static source-to-SMT allocation/trailer/padding components; no target execution."""
import copy,json,re,subprocess
from recover_daemon_list_output import ROOT,P,FLAGS,CS,sha,h,build,BLOCKS,EDGES,SCOPE
MASK64=(1<<64)-1
def bv(v,w=64):return '#x'+format(v&((1<<w)-1),'0'+str(w//4)+'x')
def split(s):return re.split(r',\s*(?![^\[]*\])',s)

class StaticSSA:
 """Straight-line bit-vector certificate builder; named loads are component inputs.
 No machine state, target memory, API, indirect branch or original CPU code runs.
 """
 def __init__(self,initial,loads=None,namespace=''):self.r=dict(initial);self.loads=loads or {};self.namespace=namespace;self.defs=[];self.sites=[];self.stores=[];self.reads=[];self.flags={}
 def get(self,token,width=None):
  token=token.strip();natural=32 if token.startswith('w')else 64;width=width or natural
  if token.startswith('#'):return bv(int(token[1:],0),width)
  if token in('xzr','wzr'):return bv(0,width)
  key='sp'if token=='sp'else int(token[1:]);e=self.r[key]
  if natural==32:e=f'((_ extract 31 0) {e})'
  if natural<width:e=f'((_ zero_extend {width-natural}) {e})'
  if natural>width:e=f'((_ extract {width-1} 0) {e})'
  return e
 def put(self,rd,e):
  w=32 if rd.startswith('w')else 64;n=self.namespace+'v'+str(len(self.defs));self.defs.append(f'(define-fun {n} () (_ BitVec {w}) {e})');key='sp'if rd=='sp'else int(rd[1:]);self.r[key]=f'((_ zero_extend 32) {n})'if w==32 else n
 def operand(self,token,width,shift=None):
  e=self.get(token,width)
  if not shift:return e
  kind,*rest=shift.split()
  if kind in('uxtw','sxtw'):
   if kind=='sxtw':e=f'((_ sign_extend 32) {self.get(token,32)})'
   return f'(bvshl {e} {bv(int(rest[0][1:],0),width)})'if rest else e
  amount=rest[0];x=self.get(amount,width)if not amount.startswith('#')else bv(int(amount[1:],0),width)
  if kind=='ror'and amount.startswith('#'):return f'((_ rotate_right {int(amount[1:],0)%width}) {e})'
  assert kind in('lsl','lsr'),shift
  x=f'(bvand {x} {bv(width-1,width)})';return f'({"bvshl"if kind=="lsl"else"bvlshr"} {e} {x})'
 def address(self,mem):
  p=split(mem.strip('[]'));e=self.get(p[0],64)
  if len(p)>1:e=f'(bvadd {e} {self.operand(p[1],64,p[2]if len(p)>2 else None)})'
  return e
 def compare(self,a,b,w,cmn=False):
  if cmn:
   total=f'(bvadd {a} {b})';carry=f'(bvult {total} {a})';self.flags={'eq':f'(= {total} {bv(0,w)})','ne':f'(distinct {total} {bv(0,w)})','lo':f'(not {carry})','hi':f'(and {carry} (distinct {total} {bv(0,w)}))'}
  else:self.flags={'eq':f'(= {a} {b})','ne':f'(distinct {a} {b})','lo':f'(bvult {a} {b})','hi':f'(bvugt {a} {b})','lt':f'(bvslt {a} {b})','ge':f'(bvsge {a} {b})'}
 def run(self,fragment,end):
  for i in fragment['instructions']:
   if int(i['ea'],16)>=end:break
   mn=i['mnemonic'];p=split(i['operands']);rd=p[0];w=32 if rd.startswith('w')else 64;pc=i['ea']
   if mn=='mov':self.put(rd,self.get(p[1],w))
   elif mn=='movk':
    imm=int(p[1][1:],0);shift=int(p[2].split('#')[1],0);mask=0xffff<<shift;self.put(rd,f'(bvor (bvand {self.get(rd,w)} {bv(~mask,w)}) {bv(imm<<shift,w)})')
   elif mn in('add','sub','eor','orr','and','bic','mul'):
    op={'add':'bvadd','sub':'bvsub','eor':'bvxor','orr':'bvor','and':'bvand','bic':'bvand','mul':'bvmul'}[mn];rhs=self.operand(p[2],w,p[3]if len(p)>3 else None)
    if mn=='bic':rhs=f'(bvnot {rhs})'
    self.put(rd,f'({op} {self.get(p[1],w)} {rhs})')
   elif mn=='madd':self.put(rd,f'(bvadd (bvmul {self.get(p[1],w)} {self.get(p[2],w)}) {self.get(p[3],w)})')
   elif mn in('lsl','lsr','ror'):self.put(rd,self.operand(p[1],w,mn+' '+p[2]))
   elif mn in('cmp','cmn'):
    self.compare(self.get(p[0],w),self.operand(p[1],w,p[2]if len(p)>2 else None),w,mn=='cmn')
   elif mn=='cset':self.put(rd,f'(ite {self.flags[p[1]]} {bv(1,w)} {bv(0,w)})')
   elif mn=='csel':self.put(rd,f'(ite {self.flags[p[3]]} {self.get(p[1],w)} {self.get(p[2],w)})')
   elif mn in('ldr','ldrb'):
    value,bits=self.loads[pc];assert bits==(8 if mn=='ldrb'else w)
    try:address=self.address(p[1])
    except KeyError:address=None
    self.reads.append({'site':pc,'address':address,'width_bits':bits,'input':value})
    self.put(rd,f'((_ zero_extend {w-bits}) {value})'if bits<w else value)
   elif mn in('str','strb'):
    bits=8 if mn=='strb'else w;v=self.get(rd,w);v=f'((_ extract 7 0) {v})'if bits==8 else v
    self.stores.append({'site':pc,'address':self.address(p[1]),'value':v,'width_bits':bits})
    if len(p)>2:
     base=p[1].strip('[]');self.put(base,f'(bvadd {self.get(base,64)} {self.get(p[2],64)})')
   else:raise AssertionError((pc,mn,p))
   self.sites.append(pc)
  return self
 def prefix(self):return '\n'.join(self.defs)+'\n'
 def record(self):return {'source_sites':self.sites,'SSA_definitions':len(self.defs),'stores':self.stores,'reads':self.reads}

PATTERNS='''
caller|ldr|x21, [sp, #0x1c10]
caller|add|x19, x19, #0x210
caller|add|x8, x8, #0x378
entry|str|x22, [sp, #0x7de0]
entry|str|x8, [x14, #0x860]
entry|cmp|x21, #0
entry|mov|w6, #0x9d88
head|ldr|x9, [x21]
sum_guard|ldr|w13, [x9, #0x10]
sum_guard|cmn|w13, w8
sum_guard|cset|w14, lo
sum_step|add|w8, w13, w8
sum_step|ldr|x9, [x9]
allocate|eor|w0, w8, w9
allocate|str|x0, [sp, #0x5af8]
allocate|cmp|x0, #0
allocate|mov|w6, #0x9d85
copy_setup|ldr|x11, [x9, #0x18]
byte_body|ldrb|w16, [x16]
byte_body|strb|w16, [x13], #0xffffffffffffffff
byte_body|sub|x12, x12, #1
byte_body|sub|x15, x15, #8
padding|strb|wzr, [x12, x9]
publish|ldr|x9, [x9, #0x860]
publish|str|x8, [x9]
publish|ldr|w8, [x8, #0x1308]
publish|str|w8, [x19]
publish|ldr|x22, [sp, #0x7de0]
publish|mov|w10, #1
publish|mov|w6, #0xc651
return|braa|x22, x17
'''
def verify(s):
 assert s['daemon_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and s['static_scope']==SCOPE
 assert set(s['fragments'])==set(BLOCKS)
 for n,f in s['fragments'].items():
  a=int(f['start'],16);bb=bytes.fromhex(f['bytes']);ii=list(CS.disasm(bb,a));assert a==BLOCKS[n]and len(bb)==4*len(ii)==int(f['end'],16)-a and h(bb)==f['sha256']
  assert f['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]and ii[-1].mnemonic=='braa'
 rows=[]
 for line in PATTERNS.strip().splitlines():
  n,mn,op=line.split('|');hits=[i for i in s['fragments'][n]['instructions']if(i['mnemonic'],i['operands'])==(mn,op)];assert hits,(n,mn,op);rows.extend({'role':n,**i}for i in hits)
 assert[(r['role'],r['source'],int(r['index'],16),int(r['target'],16))for r in s['branches']]==EDGES
 for r in s['branches']:
  w=int(r['pointer_word'],16);assert w>>63 and(w>>32&65535)==r['modifier_u16']and not(w>>48&1)and not(w>>49&3)
  assert int(r['slot'],16)==0x101039ef0+8*int(r['index'],16)
 b=s['malloc_bank'];l,rr=bytes.fromhex(b['left_bytes']),bytes.fromhex(b['right_bytes']);vals=[i^rr[l[i]^0xa]for i in range(256)];assert vals==b['results_256']and set(vals)=={0xea}and b['target']=='libSystem/_malloc'
 assert s['malloc_call']['target']=='libSystem/_malloc'and s['malloc_call']['slot']=='0x10109ff58'and s['malloc_import']['symbol']=='_malloc'and s['malloc_import']['total_addend']==0
 assert[s['phase_u32']for s in s['phase_constraints']if s['all_selected_pointer_constraints_match']]==['0x1593']and len(s['phase_constraints'])==23
 # W8/W9 survive the intervening controller lookup before the actual W0 XOR.
 ii=[i for i in s['fragments']['allocate']['instructions']if 0x1006c312c<=int(i['ea'],16)<0x1006c3170]
 assert all(split(i['operands'])[0]not in('w8','x8','w9','x9')for i in ii)
 assert s['verified_source_counts']['IDA_bytes_compared']==168 and all(s[k]is False for k in FLAGS)
 return rows

def mismatch(*terms):return '(assert (or '+' '.join(terms)+'))'
def distinct(a,b):return f'(distinct {a} {b})'
def z32(e):return f'((_ zero_extend 32) {e})'

def proofs(s):
 f=s['fragments'];trans={};qs=[]
 decl='(declare-fun T () (_ BitVec 32)) (declare-fun K () (_ BitVec 64))\n'
 pad='(bvsub #x00000010 (bvand (bvadd T #x0000000a) #x0000000f))'
 size=StaticSSA({8:z32('T'),11:bv(0x6ef2),'sp':'K'}).run(f['size'],0x10082d414);trans['size']=size.record()
 alloc=StaticSSA({8:z32('T'),9:size.r[9],23:bv(0x8435),'sp':'K'});alloc.defs=list(size.defs);alloc.run(f['allocate'],0x1006c312c)
 trans['allocation']=alloc.record();trans['allocation']['SSA_definitions']-=len(size.defs);trans['allocation']['prefix_definitions_reused']=len(size.defs);raw=alloc.stores[-1]['value'];L=f'(bvadd T {pad} #x0000000a)';w0=f'(bvxor {alloc.get("w8")} {alloc.get("w9")})'
 body=decl+alloc.prefix()+mismatch(distinct(size.get('w20'),f'(bvadd {pad} #x081b1b9c)'),distinct(size.get('w23'),'#x00008435'),distinct(size.flags['lo'],'(bvule T #xffffffe5)'),distinct(w0,L),distinct(raw,f'(bvxor {L} #x8b3dc651)'),distinct(alloc.get('w24'),'#x00004383'))
 qs.append(('size_padding_allocation_all32',body))
 header=StaticSSA({0:'D',8:z32('T'),10:bv(0x6dca),20:z32('(bvadd P #x081b1b9c)'),'sp':'K'}).run(f['trailing_record'],0x100917bec);trans['trailing_record']=header.record();assert len(header.stores)==10
 body=decl+'(declare-fun D () (_ BitVec 64)) (declare-fun P () (_ BitVec 32))\n(assert (and (bvuge P #x00000001) (bvule P #x00000010)))\n(assert (bvule T #xffffffe5))\n'+header.prefix();claims=[]
 expected=['#x00']*4+['#x50','#xdb']+[f'((_ extract {31-j*8} {24-j*8}) P)'for j in range(4)]
 for j,(st,val)in enumerate(zip(header.stores,expected)):
  assert st['width_bits']==8;claims.extend([distinct(st['address'],f'(bvadd D {z32("T")} {bv(j)})'),distinct(st['value'],val)])
 body+=mismatch(*claims);qs.append(('trailing_record_exact_addresses_and_bytes',body))
 padssa=StaticSSA({9:'I',12:'TAIL',13:f'(bvadd {z32("P")} #x00000000049bbb99)',10:bv(0x6dca),14:bv(0x3f1),'sp':'K'}).run(f['padding'],0x1006d6a90);trans['padding']=padssa.record();assert len(padssa.stores)==1
 body='(declare-fun P () (_ BitVec 32)) (declare-fun I () (_ BitVec 64)) (declare-fun TAIL () (_ BitVec 64)) (declare-fun K () (_ BitVec 64))\n(assert (and (bvuge P #x00000001) (bvule P #x00000010) (bvult I ((_ zero_extend 32) P))))\n'+padssa.prefix()
 body+=mismatch(distinct(padssa.stores[0]['address'],'(bvadd TAIL I)'),distinct(padssa.stores[0]['value'],'#x00'),distinct(padssa.get('x16'),'(bvadd I #x0000000000000001)'),distinct(padssa.get('w9'),'(ite (bvult (bvadd I #x0000000000000001) ((_ zero_extend 32) P)) #x00006e3b #x00006dca)'))
 qs.append(('padding_iteration_all_valid_counts',body))
 sums=StaticSSA({8:z32('A'),12:bv(0x6ef2),'sp':'K'},loads={'0x1006875d0':('N',32)}).run(f['sum_guard'],0x1006875ec);trans['sum_guard']=sums.record()
 body='(declare-fun A () (_ BitVec 32)) (declare-fun N () (_ BitVec 32)) (declare-fun K () (_ BitVec 64))\n'+sums.prefix()
 fit=f'(bvule (bvadd {z32("A")} {z32("N")}) #x00000000ffffffff)'
 body+=mismatch(distinct(sums.flags['lo'],fit),distinct(sums.get('w12'),f'(ite {fit} #x00006f62 #x00006ef2)'))
 qs.append(('node_length_sum_carry_partition_all32',body))
 # This is uniqueness inside the finite original continuation-fixup catalog,
 # conditional on the selected entry and both pointer-gate bindings, not proof
 # of the caller's actual W22 producer or successful hardware PAC.
 candidates=s['phase_constraints'];allowed='(or '+' '.join(f'(= C {bv(int(r["phase_u32"],16),32)})'for r in candidates)+')'
 valid=[r for r in candidates if r['all_selected_pointer_constraints_match']]
 cont=StaticSSA({10:z32('Success'),'sp':'K'},loads={'0x10090f88c':(bv(0x6cf4),64)},namespace='r_').run(f['continuation'],0x10090f8b0);trans['continuation']=cont.record()
 body='(declare-fun C () (_ BitVec 32)) (declare-fun Success () (_ BitVec 32)) (declare-fun K () (_ BitVec 64))\n(assert (or (= Success #x00000000) (= Success #x00000001)))\n(assert '+allowed+')\n(assert (or '+' '.join(f'(= C {bv(int(r["phase_u32"],16),32)})'for r in valid)+'))\n'+cont.prefix()+mismatch(distinct('C','#x00001593'),distinct(cont.get('w10'),'(ite (= Success #x00000000) #x00001a56 #x0000344d)'))
 qs.append(('original_catalog_compatible_phase_unique',body))
 # Publication of D and encoded L through caller-produced aliases, with exact
 # 8 B /4 B width and preservation of every other frame byte.
 body='(declare-fun K () (_ BitVec 64)) (declare-fun D () (_ BitVec 64)) (declare-fun L () (_ BitVec 32)) (declare-fun probe () (_ BitVec 64)) (declare-fun M () (Array (_ BitVec 64) (_ BitVec 8)))\n'
 expr='M';items=[]
 for off,value,count in[(0x8378,'D',8),(0x1210,'(bvxor L #x8b3dc651)',4)]:
  for j in range(count):
   a=f'(bvadd K {bv(off+j)})';v=f'((_ extract {8*j+7} {8*j}) {value})';expr=f'(store {expr} {a} {v})';items.append((a,v))
 body+=f'(define-fun O () (Array (_ BitVec 64) (_ BitVec 8)) {expr})\n';terms=[distinct(f'(select O {a})',v)for a,v in items]
 terms.append('(and '+' '.join(f'(distinct probe {a})'for a,v in items)+' (distinct (select O probe) (select M probe)))')
 body+=mismatch(*terms);qs.append(('published_output_pair_exact_bytes',body))
 byte_inputs={11:'S',12:'I',13:'O',15:'(bvshl (bvadd S I) #x0000000000000003)',10:bv(0x56af),'sp':'K'}
 byte=StaticSSA(byte_inputs,loads={'0x1009c3f14':('B',8)},namespace='b_').run(f['byte_body'],0x1009c3f98)
 zero=StaticSSA(byte_inputs,loads={'0x1009c3f14':('#x00',8)},namespace='z_').run(f['byte_body'],0x1009c3f98)
 trans['byte_body']=byte.record();trans['byte_zero_input']=zero.record();assert len(byte.reads)==len(byte.stores)==1
 byte_prefix='(declare-fun S () (_ BitVec 64)) (declare-fun I () (_ BitVec 64)) (declare-fun O () (_ BitVec 64)) (declare-fun K () (_ BitVec 64)) (declare-fun B () (_ BitVec 8))\n(assert (bvule I #x00000000fffffffe))\n'+byte.prefix()
 body=byte_prefix+zero.prefix()+mismatch(distinct(byte.reads[0]['address'],'(bvadd S I)'),distinct(byte.stores[0]['address'],'O'),distinct(byte.stores[0]['value'],f'(bvxor B {zero.stores[0]["value"]})'),distinct(byte.get('x13'),'(bvsub O #x0000000000000001)'),distinct(byte.get('x11'),'S'),distinct(byte.get('w14'),'#xc7095784'),distinct(byte.get('w16'),'(ite (= I #x0000000000000000) #x0000bbe0 #x000056af)'))
 qs.append(('byte_iteration_address_xor_and_control',body))
 gate=StaticSSA({8:z32('C'),11:bv(0x72ea),9:'NODE','sp':'K'},loads={'0x100756780':('N',32)},namespace='g_').run(f['node_gate'],0x1007567c4)
 trans['node_gate']=gate.record()
 setup=StaticSSA(gate.r,loads={'0x10087bbbc':('S',64),'0x10087bbe8':('TABLE',64),'0x10087bbec':('FN',64)},namespace='s_');setup.r[0]='D';setup.defs=list(gate.defs);setup.run(f['copy_setup'],0x10087bc1c)
 trans['copy_setup']=setup.record();trans['copy_setup']['SSA_definitions']-=len(gate.defs);trans['copy_setup']['prefix_definitions_reused']=len(gate.defs)
 # Restore the source-derived constant register after the final byte, then
 # verify the node-level continuation and the forward next-node step.
 after=StaticSSA({14:bv(0xc7095784),9:'NODE','sp':'K'},loads={'0x1006f8abc':('N',32)},namespace='a_').run(f['copy_done'],0x1006f8aec);trans['copy_done']=after.record()
 nxt=StaticSSA({8:z32('C'),13:z32('N'),12:bv(0x4383),9:'NODE','sp':'K'},loads={'0x100901a24':('NEXT',64)},namespace='n_').run(f['next_node'],0x100901a44);trans['next_node']=nxt.record()
 body='(declare-fun C () (_ BitVec 32)) (declare-fun N () (_ BitVec 32)) (declare-fun D () (_ BitVec 64)) (declare-fun S () (_ BitVec 64)) (declare-fun NODE () (_ BitVec 64)) (declare-fun NEXT () (_ BitVec 64)) (declare-fun K () (_ BitVec 64)) (declare-fun TABLE () (_ BitVec 64)) (declare-fun FN () (_ BitVec 64))\n'+setup.prefix()+after.prefix()+nxt.prefix()
 expected_dest=f'(bvsub (bvadd D {z32("C")} {z32("N")}) #x0000000000000001)'
 setup_bad='(and (distinct N #x00000000) (or '+distinct(setup.get('x12'),f'(bvsub {z32("N")} #x0000000000000001)')+' '+distinct(setup.get('x13'),expected_dest)+' '+distinct(setup.get('x15'),f'(bvshl (bvsub (bvadd S {z32("N")}) #x0000000000000001) #x0000000000000003)')+'))'
 body+=mismatch(distinct(gate.get('w11'),'(ite (= N #x00000000) #x000072ea #x00007309)'),setup_bad,distinct(gate.get('w10'),'#x000056af'),distinct(after.get('w10'),'#x0000567c'),distinct(after.get('w12'),'#x00004383'),distinct(nxt.get('w8'),'(bvadd C N)'),distinct(nxt.get('w10'),'#x00006dca'),distinct(nxt.get('w12'),'(ite (= NEXT #x0000000000000000) #x00004383 #x00004396)'))
 qs.append(('node_copy_setup_and_next_node_control',body))
 entry=StaticSSA({8:'OUT',19:'LEN',21:'OBJECT',22:bv(0x1593),9:bv(0x484f),'sp':'K'},loads={'0x1006bc14c':('TABLE',64),'0x1006bc150':('SAVED',64)},namespace='e_').run(f['entry'],0x1006bc198);trans['entry_control']=entry.record()
 head=StaticSSA({9:bv(0x484f),21:'OBJECT','sp':'K'},loads={'0x10075b820':('HEAD',64)},namespace='j_').run(f['head'],0x10075b83c);trans['head_control']=head.record()
 step=StaticSSA({11:bv(0x6cf4),8:z32('A'),13:z32('N'),9:'NODE','sp':'K'},loads={'0x1008fdb0c':('NEXT',64)},namespace='k_').run(f['sum_step'],0x1008fdb2c);trans['sum_step']=step.record()
 first=StaticSSA({24:bv(0x4383),21:'OBJECT','sp':'K'},loads={'0x100708930':('HEAD',64)},namespace='i_').run(f['copy_init'],0x10070895c);trans['copy_initialization']=first.record()
 prep=StaticSSA(header.r,loads={'0x100917bf0':('D',64),'0x100917bfc':('(bvadd P #x081b1b9c)',32)},namespace='p_');prep.defs=list(header.defs)
 # Continue only the suffix; the prefix's source stores remain in its own ledger.
 suffix={'instructions':[i for i in f['trailing_record']['instructions']if int(i['ea'],16)>=0x100917bec]};prep.run(suffix,0x100917c64)
 trans['padding_setup']=prep.record();trans['padding_setup']['SSA_definitions']-=len(header.defs);trans['padding_setup']['prefix_definitions_reused']=len(header.defs)
 body='(declare-fun OUT () (_ BitVec 64))(declare-fun LEN () (_ BitVec 64))(declare-fun OBJECT () (_ BitVec 64))(declare-fun HEAD () (_ BitVec 64))(declare-fun NEXT () (_ BitVec 64))(declare-fun NODE () (_ BitVec 64))(declare-fun K () (_ BitVec 64))(declare-fun TABLE () (_ BitVec 64))(declare-fun SAVED () (_ BitVec 64))(declare-fun D () (_ BitVec 64))(declare-fun T () (_ BitVec 32))(declare-fun P () (_ BitVec 32))(declare-fun A () (_ BitVec 32))(declare-fun N () (_ BitVec 32))\n(assert (and (bvuge P #x00000001)(bvule P #x00000010)(bvule T #xffffffe5)))\n'+entry.prefix()+head.prefix()+step.prefix()+first.prefix()+prep.prefix()
 body+=mismatch(distinct(entry.get('w8'),'(ite (= OBJECT #x0000000000000000) #x0000486d #x0000484f)'),distinct(entry.get('w10'),'#x00000000'),distinct(head.get('w10'),'(ite (= HEAD #x0000000000000000) #x0000abd6 #x0000ab7e)'),distinct(head.get('w12'),'#x00006ef2'),distinct(head.get('w8'),'#x00000000'),distinct(step.get('w10'),'(ite (= NEXT #x0000000000000000) #x0000abd6 #x0000ab7e)'),distinct(step.get('w8'),'(bvadd A N)'),distinct(step.get('w11'),'#x00006ef2'),distinct(first.get('w12'),'(ite (= HEAD #x0000000000000000) #x00004383 #x00004396)'),distinct(first.get('w11'),'#x000072ea'),distinct(first.get('w10'),'#x00006dca'),distinct(first.get('w8'),'#x00000000'),distinct(prep.get('x12'),f'(bvadd D {z32("T")} #x000000000000000a)'),distinct(prep.get('x13'),f'(bvadd {z32("P")} #x00000000049bbb99)'),distinct(prep.get('x8'),'D'),distinct(prep.get('x9'),'#x0000000000000000'),distinct(prep.get('w15'),'#x00006e3b'))
 qs.append(('entry_list_pass_and_padding_setup_control',body))
 out=[]
 for name,body in qs:
  assert body.count('(')==body.count(')'),name
  q='(set-option :timeout 20000)\n(set-logic QF_AUFBV)\n'+body+'\n(check-sat)\n';r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);assert r.returncode==0 and r.stdout.strip()=='unsat'and not r.stderr,(name,r.stdout,r.stderr)
  out.append({'name':name,'query':q,'result':'unsat','scope':'Static arithmetic/byte-array components. Original tables, compatible phase, stable finite list/frame epochs, valid owners and normal malloc return are premises. Complete payload-byte semantics, native occurrence/PAC/ownership/delivery and the actual incoming phase remain unproved.'})
 observations=[]
 for source,index in[(0x10001000,0),(0x10001000,1),(0x10001008,0)]:
  q='(set-logic QF_BV)\n'+byte_prefix+f'(assert (= S {bv(source)}))(assert (= I {bv(index)}))(assert (= B #x00))\n(define-fun observed () (_ BitVec 8) {byte.stores[0]["value"]})\n(check-sat)\n(get-value (observed))\n'
  r=subprocess.run(['/opt/homebrew/bin/z3','-in'],input=q,capture_output=True,text=True);m=re.search(r'\(observed #x([0-9a-f]{2})\)',r.stdout);assert r.returncode==0 and r.stdout.startswith('sat\n')and m and not r.stderr
  observations.append({'source_parameter_u64':hex(source),'index_u64':hex(index),'input_byte':'0x00','output_byte':'0x'+m[1],'query':q,'result':r.stdout,'scope':'Finite mathematical SSA valuation, no mapped buffer or executed native/guest instruction. These demonstrate an address-dependent value transform and do not establish the producer inverse.'})
 assert[r['output_byte']for r in observations]==['0xa1','0xe3','0x35']
 return {'queries':out,'translations':trans,'byte_value_observations':observations}

def models():
 sizes=[]
 totals=list(range(32))+[0xffffffe0,0xffffffe5,0xffffffe6,0xfffffff0,0xffffffff]
 for t in totals:
  p=16-((t+10)&15);L=t+p+10;admit=t+p<0xfffffff6
  assert 1<=p<=16 and L%16==0 and admit==(t<=0xffffffe5)
  if admit:assert 16<=L<=0xfffffff0
  sizes.append({'total_bytes':t,'zero_padding_bytes':p,'allocation_bytes':L,'admitted':admit})
 pads=[]
 for p in range(1,17):
  writes=list(range(p));assert len(writes)==p and writes[-1]==p-1;pads.append({'padding_bytes':p,'written_offsets':writes,'last_edge':'publish'})
 sums=[]
 for a,n in[(0,0),(0,0xffffffff),(1,0xffffffff),(0xffffffff,1),(0xfffffffe,1),(0x80000000,0x80000000)]:sums.append({'A':a,'N':n,'sum_u64':a+n,'fits_u32':a+n<=0xffffffff})
 return {'size_cases':sizes,'padding_cases':pads,'padding_iteration_cases':sum(range(1,17)),'sum_cases':sums,'scope':'Analyst-written integer boundary/list-padding models; no target fixtures, buffers, allocator calls or requests are executed.'}

def alterations(s):
 def ins(q,n,ea,op):next(i for i in q['fragments'][n]['instructions']if i['ea']==ea).update(operands=op)
 changes=[('node_size_width',lambda q:ins(q,'sum_guard','0x1006875d0','x13, [x9, #0x10]')),
 ('carry_direction',lambda q:ins(q,'sum_guard','0x1006875d8','w14, hi')),
 ('allocation_pointer_slot',lambda q:ins(q,'allocate','0x1006c3194','x0, [sp, #0x5af0]')),
 ('padding_value',lambda q:ins(q,'padding','0x1006d6a48','w13, [x12, x9]')),
 ('output_extent_width',lambda q:ins(q,'publish','0x10068f644','x8, [x19]')),
 ('wrong_call_target',lambda q:q['malloc_bank'].update(target='libSystem/_free')),
 ('wrong_phase',lambda q:next(r for r in q['phase_constraints']if r['phase_u32']=='0x1593').update(all_selected_pointer_constraints_match=False)),
 ('native_claim',lambda q:q.update(native_peer_identity_proved=True))]
 out=[]
 for name,change in changes:
  q=copy.deepcopy(s);change(q)
  try:verify(q)
  except AssertionError:out.append({'alteration':name,'rejected':True})
  else:raise AssertionError('Accepted altered evidence '+name)
 return out

def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();rows=verify(s);pr=proofs(s);mm=models();neg=alterations(s)
 c={'generator_sha256':sha(__file__),'dependencies':{'recover_'+P+'.py':sha(ROOT/('recover_'+P+'.py'))},'source_recapture_match':True,'instruction_assertions':rows,'proofs':pr,'models':mm,'alterations':neg,'solver':{'path':'/opt/homebrew/bin/z3','sha256':sha('/opt/homebrew/bin/z3')},
  'verified_counts':{**s['verified_source_counts'],'instruction_assertions':len(rows),'translated_source_sites':sum(len(r['source_sites'])for r in pr['translations'].values()),'unique_translated_source_sites':len({pc for r in pr['translations'].values()for pc in r['source_sites']}),'SSA_definitions':sum(r['SSA_definitions']for r in pr['translations'].values()),'component_queries_unsat':len(pr['queries']),'byte_value_observations':len(pr['byte_value_observations']),'size_boundary_cases':len(mm['size_cases']),'padding_count_cases':len(mm['padding_cases']),'padding_iteration_cases':mm['padding_iteration_cases'],'sum_boundary_cases':len(mm['sum_cases']),'rejected_evidence_alterations':len(neg)},'all_checks_pass':True,'static_scope':SCOPE,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(c['verified_counts']),flush=True)
if __name__=='__main__':main()
