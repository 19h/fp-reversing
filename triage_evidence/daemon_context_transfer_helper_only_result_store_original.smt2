; benchmark generated from python API
(set-info :status unknown)
(declare-fun comparison_record64 () (_ BitVec 64))
(assert
 (let (($x266 (and (distinct (bvadd (_ bv16 64) comparison_record64) (bvadd comparison_record64 (_ bv16 64))) true)))
(let (($x24 (bvule comparison_record64 (_ bv18446744073709551567 64))))
(let (($x25 (and (= (bvand comparison_record64 (_ bv7 64)) (_ bv0 64)) $x24)))
(and $x25 $x266)))))
(check-sat)
