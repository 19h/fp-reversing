; benchmark generated from python API
(set-info :status unknown)
(declare-fun rw_heap64 () (_ BitVec 64))
(assert
 (let (($x210 (and (distinct rw_heap64 rw_heap64) true)))
(or $x210 (and (distinct (_ bv0 64) (_ bv0 64)) true) (and (distinct (_ bv40999 64) (_ bv40999 64)) true))))
(check-sat)
