; benchmark generated from python API
(set-info :status unknown)
(assert
 (let ((?x2050 ((_ extract 31 0) ((_ zero_extend 32) (_ bv1958911945 32)))))
(and (distinct ?x2050 (bvxor (_ bv4294924696 32) (_ bv2336081489 32))) true)))
(check-sat)
