; benchmark generated from python API
(set-info :status unknown)
(declare-fun secondary_string_FP64 () (_ BitVec 64))
(declare-fun secondary_value_ref64 () (_ BitVec 64))
(assert
 (let ((?x136 (bvadd (_ bv18446744073709551488 64) secondary_string_FP64)))
(let (($x10 (and (distinct secondary_value_ref64 secondary_value_ref64) true)))
(or $x10 (and (distinct ?x136 (bvsub secondary_string_FP64 (_ bv128 64))) true) (and (distinct (_ bv32 64) (_ bv32 64)) true) (and (distinct (_ bv1536 64) (_ bv1536 64)) true) (and (distinct (_ bv29192 64) (_ bv29192 64)) true)))))
(check-sat)
