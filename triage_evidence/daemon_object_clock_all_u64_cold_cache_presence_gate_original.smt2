; benchmark generated from python API
(set-info :status unknown)
(declare-fun clock_return64 () (_ BitVec 64))
(assert
 (let (($x150 (= clock_return64 (_ bv0 64))))
(let ((?x339 (ite $x150 (_ bv40536 32) (_ bv40540 32))))
(let (($x144 (and (distinct clock_return64 clock_return64) true)))
(or $x144 (and (distinct ((_ extract 31 0) (concat (_ bv5067 61) (ite $x150 (_ bv0 1) (_ bv1 1)) (_ bv0 2))) ?x339) true))))))
(check-sat)
