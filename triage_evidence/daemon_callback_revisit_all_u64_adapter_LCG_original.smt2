; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_state64 () (_ BitVec 64))
(assert
 (let (($x23 (and (distinct (bvadd (_ bv1 64) (bvmul (_ bv11973 64) callback_state64)) (bvadd (bvmul callback_state64 (_ bv11973 64)) (_ bv1 64))) true)))
(and true $x23)))
(check-sat)
