(set-option :timeout 30000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun selector32 () (_ BitVec 32))
(assert
 (let (($x245 (ite (bvsle (_ bv2336081491 32) (bvxor selector32 (_ bv2336081489 32))) (= (_ bv2336081491 32) (bvxor selector32 (_ bv2336081489 32))) (= (_ bv2336081488 32) (bvxor selector32 (_ bv2336081489 32))))))
(and (distinct $x245 (or (= (_ bv1 32) selector32) (= (_ bv2 32) selector32))) true)))
(check-sat)
