; benchmark generated from python API
(set-info :status unknown)
(declare-fun less_record64 () (_ BitVec 64))
(assert
 (let (($x23 (bvule less_record64 (_ bv18446744073709551579 64))))
(let (($x24 (and (= (bvand less_record64 (_ bv7 64)) (_ bv0 64)) $x23)))
(and $x24 (and (distinct less_record64 less_record64) true)))))
(check-sat)
