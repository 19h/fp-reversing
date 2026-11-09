; benchmark generated from python API
(set-info :status unknown)
(declare-fun string_FP64 () (_ BitVec 64))
(assert
 (let ((?x23 (bvadd (_ bv18446744073709551488 64) string_FP64)))
(let (($x25 (and (distinct ?x23 (bvsub string_FP64 (_ bv128 64))) true)))
(or $x25 (and (distinct (bvadd (_ bv18446744073709551472 64) string_FP64) (bvsub string_FP64 (_ bv144 64))) true) (and (distinct (_ bv10 64) (_ bv10 64)) true) (and (distinct (_ bv34939 64) (_ bv34939 64)) true)))))
(check-sat)
