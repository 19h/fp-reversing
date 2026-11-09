; benchmark generated from python API
(set-info :status unknown)
(assert
 (let (($x99 (and (distinct (_ bv0 32) (_ bv0 32)) true)))
(let (($x11 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv10985 32))) (_ bv10985 32)) true)))
(or $x11 $x99))))
(check-sat)
