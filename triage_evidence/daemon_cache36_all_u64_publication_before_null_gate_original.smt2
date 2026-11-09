; benchmark generated from python API
(set-info :status unknown)
(declare-fun cache36_return64 () (_ BitVec 64))
(assert
 (let (($x18 (and (distinct cache36_return64 cache36_return64) true)))
(or $x18 (and (distinct (_ bv4312557632 64) (_ bv4312557632 64)) true))))
(check-sat)
