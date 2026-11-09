; benchmark generated from python API
(set-info :status unknown)
(declare-fun out_record64 () (_ BitVec 64))
(declare-fun out_frame64 () (_ BitVec 64))
(assert
 (let (($x27 (and (= (bvand out_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge out_frame64 (_ bv429496729600 64)) (bvule out_frame64 (_ bv429496792096 64)))))
(let (($x34 (and $x27 (= out_record64 (bvadd out_frame64 (_ bv2808 64))) (= (bvand out_record64 (_ bv7 64)) (_ bv0 64)))))
(and $x34 (and (distinct out_record64 out_record64) true)))))
(check-sat)
