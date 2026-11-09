; benchmark generated from python API
(set-info :status unknown)
(assert
 (let (($x100 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv26284 32))) (_ bv26284 32)) true)))
(or $x100 $x100)))
(check-sat)
