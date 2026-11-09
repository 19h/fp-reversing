; benchmark generated from python API
(set-info :status unknown)
(declare-fun out_data64 () (_ BitVec 64))
(declare-fun out_frame64 () (_ BitVec 64))
(assert
 (let (($x27 (and (= (bvand out_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge out_frame64 (_ bv429496729600 64)) (bvule out_frame64 (_ bv429496792096 64)))))
(and $x27 (and (distinct out_data64 out_data64) true))))
(check-sat)
