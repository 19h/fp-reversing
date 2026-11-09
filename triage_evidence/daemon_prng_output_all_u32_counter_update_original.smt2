; benchmark generated from python API
(set-info :status unknown)
(declare-fun out_counter32 () (_ BitVec 32))
(declare-fun out_frame64 () (_ BitVec 64))
(assert
 (let ((?x656 (bvadd out_counter32 (_ bv1 32))))
(let (($x678 (bvugt out_counter32 (_ bv5119 32))))
(let ((?x642 (ite $x678 (_ bv0 32) ?x656)))
(let (($x27 (and (= (bvand out_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge out_frame64 (_ bv429496729600 64)) (bvule out_frame64 (_ bv429496792096 64)))))
(and $x27 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) ?x642)) ?x642) true)))))))
(check-sat)
