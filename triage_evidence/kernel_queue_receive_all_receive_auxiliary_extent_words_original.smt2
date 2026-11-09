; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_aux_extent16 () (_ BitVec 16))
(declare-fun qr_aux_limit32 () (_ BitVec 32))
(assert
 (let ((?x101 ((_ extract 31 0) ((_ zero_extend 32) ((_ zero_extend 16) qr_aux_extent16)))))
(and (distinct (not (bvuge ((_ extract 31 0) (concat (_ bv0 32) qr_aux_limit32)) ?x101)) (bvult qr_aux_limit32 ((_ zero_extend 16) qr_aux_extent16))) true)))
(check-sat)
