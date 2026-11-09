; benchmark generated from python API
(set-info :status unknown)
(declare-fun secondary_number_out64 () (_ BitVec 64))
(declare-fun secondary_value_ref64 () (_ BitVec 64))
(assert
 (let (($x10 (and (distinct secondary_value_ref64 secondary_value_ref64) true)))
(or $x10 (and (distinct (_ bv3 64) (_ bv3 64)) true) (and (distinct secondary_number_out64 secondary_number_out64) true) (and (distinct (_ bv34370 64) (_ bv34370 64)) true))))
(check-sat)
