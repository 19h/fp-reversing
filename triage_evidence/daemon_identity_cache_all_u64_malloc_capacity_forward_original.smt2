; benchmark generated from python API
(set-info :status unknown)
(declare-fun identity_A64 () (_ BitVec 64))
(assert
 (let (($x18 (and (distinct identity_A64 identity_A64) true)))
(or $x18 (and (distinct (_ bv27300 64) (_ bv27300 64)) true))))
(check-sat)
