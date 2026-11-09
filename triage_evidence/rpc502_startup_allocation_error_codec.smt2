(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(assert
 (and (distinct (_ bv4294925268 32) (bvxor (bvor (bvand (_ bv40325 32) (_ bv65535 32)) (bvshl (_ bv29890 32) (_ bv16 32))) (_ bv2336081489 32))) true))
(check-sat)
