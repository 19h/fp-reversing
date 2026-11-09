; benchmark generated from python API
(set-info :status unknown)
(assert
 (let (($x11 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv10985 32))) (_ bv10985 32)) true)))
(or (and (distinct ((_ extract 31 0) (_ bv37750 64)) (_ bv37750 32)) true) $x11 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv21026 32))) (_ bv21026 32)) true))))
(check-sat)
