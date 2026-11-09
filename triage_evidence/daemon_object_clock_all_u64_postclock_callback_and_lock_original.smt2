; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_return64 () (_ BitVec 64))
(assert
 (let (($x144 (and (distinct clock_return64 clock_return64) true)))
(or (and (distinct (_ bv4305294032 64) (_ bv4305294032 64)) true) $x144 (and (distinct ((_ extract 31 0) (_ bv16583 64)) (_ bv16583 32)) true) (and (distinct ((_ extract 31 0) (_ bv17532 64)) (_ bv17532 32)) true))))
(check-sat)
