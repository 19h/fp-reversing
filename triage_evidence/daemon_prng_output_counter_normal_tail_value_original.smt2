; benchmark generated from python API
(set-info :status unknown)
(declare-fun out_frame64 () (_ BitVec 64))
(assert
 (let (($x737 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv1 32))) (_ bv1 32)) true)))
(let (($x27 (and (= (bvand out_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge out_frame64 (_ bv429496729600 64)) (bvule out_frame64 (_ bv429496792096 64)))))
(and $x27 $x737))))
(check-sat)
