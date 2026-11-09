; benchmark generated from python API
(set-info :status unknown)
(declare-fun provider_result64 () (_ BitVec 64))
(assert
 (let (($x97 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv0 32))) (_ bv0 32)) true)))
(or $x97 (and (distinct ((_ extract 31 0) provider_result64) ((_ extract 31 0) provider_result64)) true))))
(check-sat)
