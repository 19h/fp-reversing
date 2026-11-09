(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun inherited_w27 () (_ BitVec 32))
(declare-fun dispatch_seed_u32 () (_ BitVec 32))
(declare-fun ready_u8 () (_ BitVec 8))
(assert
 (let ((?x10 (bvor (bvadd dispatch_seed_u32 (_ bv4294949200 32)) inherited_w27)))
(let ((?x22 (bvadd (bvadd (bvmul (bvxor dispatch_seed_u32 (_ bv18579 32)) (_ bv18016 32)) ?x10) (_ bv23571 32))))
(let (($x44 (= ready_u8 (_ bv1 8))))
(let ((?x24 (bvxor (bvmul ?x22 (ite (= (_ bv1 32) ((_ zero_extend 24) ready_u8)) (_ bv1 32) (_ bv0 32))) dispatch_seed_u32)))
(and (distinct ?x24 (bvxor dispatch_seed_u32 (ite $x44 ?x22 (_ bv0 32)))) true))))))
(check-sat)
