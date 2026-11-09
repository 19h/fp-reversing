; benchmark generated from python API
(set-info :status unknown)
(declare-fun request64 () (_ BitVec 64))
(assert
 (let (($x325 (and (distinct request64 request64) true)))
(or (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv1318 32))) (_ bv1318 32)) true) $x325)))
(check-sat)
