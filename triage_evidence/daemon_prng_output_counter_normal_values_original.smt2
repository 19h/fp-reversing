; benchmark generated from python API
(set-info :status unknown)
(declare-fun out_counter32 () (_ BitVec 32))
(declare-fun out_frame64 () (_ BitVec 64))
(assert
 (let ((?x685 (bvnot (bvor out_counter32 (bvadd (_ bv5119 32) (bvmul (_ bv4294967295 32) out_counter32))))))
(let ((?x513 ((_ extract 31 0) ((_ zero_extend 32) (bvashr ((_ extract 31 0) ((_ zero_extend 32) ?x685)) (bvand (_ bv31 32) (_ bv31 32)))))))
(let (($x737 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv1 32))) (_ bv1 32)) true)))
(let ((?x656 (bvadd out_counter32 (_ bv1 32))))
(let (($x405 (or (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv1 32) out_counter32))) ?x656) true) $x737 (and (distinct ?x513 (_ bv4294967295 32)) true))))
(let (($x27 (and (= (bvand out_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge out_frame64 (_ bv429496729600 64)) (bvule out_frame64 (_ bv429496792096 64)))))
(and (and $x27 (bvule out_counter32 (_ bv5119 32))) $x405))))))))
(check-sat)
