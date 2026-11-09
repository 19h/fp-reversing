; benchmark generated from python API
(set-info :status unknown)
(declare-fun payload_pointer64 () (_ BitVec 64))
(assert
 (let (($x886 (and (distinct payload_pointer64 payload_pointer64) true)))
(or $x886 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv41 32))) (_ bv41 32)) true))))
(check-sat)
