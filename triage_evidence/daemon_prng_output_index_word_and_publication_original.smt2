; benchmark generated from python API
(set-info :status unknown)
(declare-fun out_index32 () (_ BitVec 32))
(declare-fun out_raw32 () (_ BitVec 32))
(declare-fun out_frame64 () (_ BitVec 64))
(assert
 (let (($x780 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (bvadd (_ bv1 32) out_index32))) (bvadd out_index32 (_ bv1 32))) true)))
(let (($x847 (or (and (distinct ((_ extract 31 0) ((_ zero_extend 32) out_raw32)) out_raw32) true) $x780 $x780)))
(let (($x27 (and (= (bvand out_frame64 (_ bv15 64)) (_ bv0 64)) (bvuge out_frame64 (_ bv429496729600 64)) (bvule out_frame64 (_ bv429496792096 64)))))
(and (and $x27 (bvule out_index32 (_ bv623 32))) $x847)))))
(check-sat)
