; benchmark generated from python API
(set-info :status unknown)
(declare-fun fallback_version32 () (_ BitVec 32))
(assert
 (let ((?x9 (bvlshr fallback_version32 (_ bv16 32))))
(let ((?x11 (bvand ?x9 (_ bv255 32))))
(let (($x463 (= ?x11 (_ bv30 32))))
(let ((?x7 (bvlshr fallback_version32 (_ bv24 32))))
(let (($x306 (= ?x7 (_ bv46 32))))
(and $x306 $x463 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) ((_ extract 31 0) ((_ zero_extend 32) (_ bv34590 32))))) (_ bv34590 32)) true))))))))
(check-sat)
