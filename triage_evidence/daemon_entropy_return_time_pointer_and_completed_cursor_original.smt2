; benchmark generated from python API
(set-info :status unknown)
(declare-fun entropy_frame64 () (_ BitVec 64))
(assert
 (let (($x180 (or (and (distinct (bvadd (_ bv1664 64) entropy_frame64) (bvadd entropy_frame64 (_ bv1664 64))) true) (and (distinct ((_ extract 31 0) (_ bv624 64)) (_ bv624 32)) true) (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv2325448032 32))) (_ bv2325448032 32)) true))))
(let (($x23 (bvule entropy_frame64 (_ bv18446744073709548575 64))))
(let (($x24 (and (= (bvand entropy_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge entropy_frame64 (_ bv8589934592 64)) $x23)))
(and $x24 $x180)))))
(check-sat)
