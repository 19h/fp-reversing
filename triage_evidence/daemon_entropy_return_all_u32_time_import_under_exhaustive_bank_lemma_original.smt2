; benchmark generated from python API
(set-info :status unknown)
(declare-fun entropy_frame64 () (_ BitVec 64))
(assert
 (let (($x23 (bvule entropy_frame64 (_ bv18446744073709548575 64))))
(let (($x24 (and (= (bvand entropy_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge entropy_frame64 (_ bv8589934592 64)) $x23)))
(and $x24 (or (and (distinct (_ bv2081423360 64) (_ bv2081423360 64)) true) (and (distinct (_ bv0 64) (_ bv0 64)) true) (and (distinct (_ bv37528 64) (_ bv37528 64)) true))))))
(check-sat)
