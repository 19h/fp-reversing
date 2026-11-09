; benchmark generated from python API
(set-info :status unknown)
(declare-fun entropy_index64 () (_ BitVec 64))
(declare-fun entropy_frame64 () (_ BitVec 64))
(assert
 (let (($x151 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv1437820334 32) ((_ extract 31 0) entropy_index64)))) (bvadd ((_ extract 31 0) entropy_index64) (_ bv1437820334 32))) true)))
(let (($x97 (or (and (distinct (bvadd (_ bv1 64) entropy_index64) (bvadd entropy_index64 (_ bv1 64))) true) $x151)))
(let (($x23 (bvule entropy_frame64 (_ bv18446744073709548575 64))))
(let (($x24 (and (= (bvand entropy_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge entropy_frame64 (_ bv8589934592 64)) $x23)))
(let (($x30 (and $x24 (bvuge entropy_index64 (_ bv1 64)) (bvule entropy_index64 (_ bv623 64)))))
(and $x30 $x97)))))))
(check-sat)
