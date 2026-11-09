(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun word32 () (_ BitVec 32))
(assert
 (let ((?x51 (bvadd (bvsub word32 (bvand (bvshl (_ bv2913300028 32) (_ bv1 32)) (bvshl word32 (_ bv1 32)))) (_ bv2913300028 32))))
(and (distinct ?x51 (bvxor word32 (_ bv2913300028 32))) true)))
(check-sat)
