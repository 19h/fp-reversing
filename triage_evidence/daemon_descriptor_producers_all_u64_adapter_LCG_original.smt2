; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_counter64 () (_ BitVec 64))
(assert
 (let (($x313 (and (distinct (bvadd (_ bv1 64) (bvmul (_ bv11965 64) producer_counter64)) (bvadd (bvmul producer_counter64 (_ bv11965 64)) (_ bv1 64))) true)))
(and true $x313)))
(check-sat)
