; benchmark generated from python API
(set-info :status unknown)
(declare-fun entropy_index64 () (_ BitVec 64))
(declare-fun entropy_frame64 () (_ BitVec 64))
(assert
 (let (($x116 (and (distinct (bvadd (_ bv4312561740 64) (concat ((_ extract 61 0) entropy_index64) (_ bv0 2))) (bvadd (_ bv4312561740 64) (bvshl entropy_index64 (_ bv2 64)))) true)))
(let (($x23 (bvule entropy_frame64 (_ bv18446744073709548575 64))))
(let (($x24 (and (= (bvand entropy_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge entropy_frame64 (_ bv8589934592 64)) $x23)))
(let (($x30 (and $x24 (bvuge entropy_index64 (_ bv1 64)) (bvule entropy_index64 (_ bv623 64)))))
(and $x30 $x116))))))
(check-sat)
