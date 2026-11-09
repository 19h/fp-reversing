(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(assert
 (let ((?x37 (bvor (bvand (_ bv24464 32) (_ bv65535 32)) (bvshl (_ bv1 32) (_ bv16 32)))))
(and (distinct ?x37 (_ bv90000 32)) true)))
(check-sat)
