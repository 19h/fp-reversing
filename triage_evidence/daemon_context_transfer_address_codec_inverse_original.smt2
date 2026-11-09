; benchmark generated from python API
(set-info :status unknown)
(declare-fun comparison_record64 () (_ BitVec 64))
(assert
 (let ((?x65 (bvxor (bvmul (bvmul (bvxor comparison_record64 (_ bv5612508312774154612 64)) (_ bv3662784551 64)) (_ bv4852040765898311575 64)) (_ bv5612508312774154612 64))))
(let (($x24 (bvule comparison_record64 (_ bv18446744073709551567 64))))
(let (($x25 (and (= (bvand comparison_record64 (_ bv7 64)) (_ bv0 64)) $x24)))
(and $x25 (and (distinct ?x65 comparison_record64) true))))))
(check-sat)
