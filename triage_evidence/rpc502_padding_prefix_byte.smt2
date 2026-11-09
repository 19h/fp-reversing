(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun reference_byte8 () (_ BitVec 8))
(declare-fun candidate_byte8 () (_ BitVec 8))
(declare-fun prior_error8 () (_ BitVec 8))
(assert
 (let ((?x10 ((_ zero_extend 24) prior_error8)))
(let ((?x106 (bvor ?x10 (bvxor ((_ zero_extend 24) candidate_byte8) ((_ zero_extend 24) reference_byte8)))))
(let ((?x6 ((_ zero_extend 24) candidate_byte8)))
(let ((?x8 ((_ zero_extend 24) reference_byte8)))
(let ((?x99 (bvxor ?x8 ?x6)))
(and (distinct (bvor (bvand ?x99 (_ bv858993459 32)) (bvand (bvxor (_ bv1655794636 32) ?x10) (bvnot ?x99))) (bvxor (_ bv1655794636 32) ?x106)) true)))))))
(check-sat)
