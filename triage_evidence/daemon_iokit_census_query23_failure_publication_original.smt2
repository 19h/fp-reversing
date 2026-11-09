; benchmark generated from python API
(set-info :status unknown)
(assert
 (let (($x99 (and (distinct (_ bv0 32) (_ bv0 32)) true)))
(let (($x97 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv0 32))) (_ bv0 32)) true)))
(let (($x123 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv20212 32))) (_ bv20212 32)) true)))
(or $x123 $x97 $x99)))))
(check-sat)
