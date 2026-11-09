; benchmark generated from python API
(set-info :status unknown)
(assert
 (let ((?x94 ((_ zero_extend 32) (_ bv1652925069 32))))
(let ((?x97 ((_ extract 31 0) ?x94)))
(let (($x75 (bvuge ?x97 ?x97)))
(or (and (distinct (= ?x97 ?x97) (= ?x97 ?x97)) true) (and (distinct $x75 $x75) true))))))
(check-sat)
