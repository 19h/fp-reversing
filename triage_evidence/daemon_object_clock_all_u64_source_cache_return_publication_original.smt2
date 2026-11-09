; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_return64 () (_ BitVec 64))
(assert
 (let (($x144 (and (distinct clock_return64 clock_return64) true)))
(or $x144 (and (distinct (_ bv4312557632 64) (_ bv4312557632 64)) true))))
(check-sat)
