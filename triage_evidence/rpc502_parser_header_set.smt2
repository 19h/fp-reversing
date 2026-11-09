(set-option :timeout 30000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun word32 () (_ BitVec 32))
(assert
 (let (($x238 (ite (bvsgt (_ bv2336081492 32) (bvxor word32 (_ bv2336081489 32))) (= (_ bv2336081490 32) (bvxor word32 (_ bv2336081489 32))) (= (_ bv2336081492 32) (bvxor word32 (_ bv2336081489 32))))))
(let (($x239 (ite (bvsgt (_ bv2336081490 32) (bvxor word32 (_ bv2336081489 32))) (= (_ bv2336081488 32) (bvxor word32 (_ bv2336081489 32))) $x238)))
(and (distinct $x239 (or (= (_ bv1 32) word32) (= (_ bv3 32) word32) (= (_ bv5 32) word32))) true))))
(check-sat)
