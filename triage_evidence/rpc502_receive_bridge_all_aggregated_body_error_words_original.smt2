; benchmark generated from python API
(set-info :status unknown)
(declare-fun rb_body_error_mask32 () (_ BitVec 32))
(assert
 (let (($x168 (= rb_body_error_mask32 (_ bv0 32))))
(let ((?x147 (concat ((_ extract 31 29) rb_body_error_mask32) (_ bv1 1) ((_ extract 27 15) rb_body_error_mask32) (_ bv1 1) ((_ extract 13 4) rb_body_error_mask32) (_ bv3 2) ((_ extract 1 0) rb_body_error_mask32))))
(and (distinct ((_ extract 31 0) (concat (_ bv0 32) (ite $x168 (_ bv0 32) ?x147))) (ite $x168 (_ bv0 32) (bvor rb_body_error_mask32 (_ bv268451852 32)))) true))))
(check-sat)
