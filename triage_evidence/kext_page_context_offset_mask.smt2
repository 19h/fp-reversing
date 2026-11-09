(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(assert
 (let ((?x159 (bvor ((_ extract 31 0) ((_ zero_extend 32) (bvsub ((_ extract 31 0) (_ bv866 64)) (_ bv864 32)))) ((_ extract 31 0) ((_ zero_extend 32) (_ bv1584 32))))))
(let ((?x168 (bvadd ((_ zero_extend 32) ?x159) (bvor (bvand (_ bv18446726481523507200 64) (_ bv18446744073709486080 64)) (bvshl (_ bv2509 64) (_ bv0 64))))))
(and (distinct ?x168 (_ bv18446726481523511295 64)) true))))
(check-sat)
