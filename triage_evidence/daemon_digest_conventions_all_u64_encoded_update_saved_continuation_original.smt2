; benchmark generated from python API
(set-info :status unknown)
(declare-fun conventions_return64 () (_ BitVec 64))
(assert
 (let (($x17 (and (distinct conventions_return64 conventions_return64) true)))
(or $x17 (and (distinct (_ bv57556 64) (_ bv57556 64)) true))))
(check-sat)
