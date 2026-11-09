; benchmark generated from python API
(set-info :status unknown)
(declare-fun entropy_frame64 () (_ BitVec 64))
(assert
 (let (($x53 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv1437820334 32))) (_ bv1437820334 32)) true)))
(let (($x63 (or (and (distinct ((_ zero_extend 32) (_ bv1 32)) (_ bv1 64)) true) $x53 $x53 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv23763 32))) (_ bv23763 32)) true) (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv1812433253 32))) (_ bv1812433253 32)) true) (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv2857146963 32))) (_ bv2857146963 32)) true) (and (distinct (_ bv4298096356 64) (_ bv4298096356 64)) true) (and (distinct (_ bv53417 64) (_ bv53417 64)) true))))
(let (($x23 (bvule entropy_frame64 (_ bv18446744073709548575 64))))
(let (($x24 (and (= (bvand entropy_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge entropy_frame64 (_ bv8589934592 64)) $x23)))
(and $x24 $x63))))))
(check-sat)
