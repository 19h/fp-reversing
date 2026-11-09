; benchmark generated from python API
(set-info :status unknown)
(declare-fun input_sized_region64 () (_ BitVec 64))
(assert
 (let (($x12 (and (distinct input_sized_region64 input_sized_region64) true)))
(or $x12 (and (distinct (_ bv0 64) (_ bv0 64)) true) (and (distinct (_ bv0 32) (_ bv0 32)) true))))
(check-sat)
