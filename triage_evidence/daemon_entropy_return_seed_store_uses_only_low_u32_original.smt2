; benchmark generated from python API
(set-info :status unknown)
(declare-fun entropy_seed32 () (_ BitVec 32))
(declare-fun entropy_high32 () (_ BitVec 32))
(declare-fun entropy_frame64 () (_ BitVec 64))
(assert
 (let (($x32 (and (distinct ((_ extract 31 0) (concat entropy_high32 entropy_seed32)) entropy_seed32) true)))
(let (($x23 (bvule entropy_frame64 (_ bv18446744073709548575 64))))
(let (($x24 (and (= (bvand entropy_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge entropy_frame64 (_ bv8589934592 64)) $x23)))
(and $x24 $x32)))))
(check-sat)
