; benchmark generated from python API
(set-info :status unknown)
(declare-fun string_FP64 () (_ BitVec 64))
(declare-fun string_CF_ref64 () (_ BitVec 64))
(assert
 (let ((?x23 (bvadd (_ bv18446744073709551488 64) string_FP64)))
(let (($x25 (and (distinct ?x23 (bvsub string_FP64 (_ bv128 64))) true)))
(or (and (distinct string_CF_ref64 string_CF_ref64) true) $x25 (and (distinct (_ bv32 64) (_ bv32 64)) true) (and (distinct (_ bv1536 64) (_ bv1536 64)) true) (and (distinct (_ bv29192 64) (_ bv29192 64)) true)))))
(check-sat)
