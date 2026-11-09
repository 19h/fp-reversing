; benchmark generated from python API
(set-info :status unknown)
(declare-fun time_status32 () (_ BitVec 32))
(declare-fun entropy_frame64 () (_ BitVec 64))
(assert
 (let (($x23 (bvule entropy_frame64 (_ bv18446744073709548575 64))))
(let (($x24 (and (= (bvand entropy_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge entropy_frame64 (_ bv8589934592 64)) $x23)))
(and $x24 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) time_status32)) time_status32) true)))))
(check-sat)
