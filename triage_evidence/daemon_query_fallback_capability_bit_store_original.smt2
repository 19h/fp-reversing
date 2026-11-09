; benchmark generated from python API
(set-info :status unknown)
(declare-fun encoded_capability32 () (_ BitVec 32))
(assert
 (let ((?x802 ((_ extract 2 0) encoded_capability32)))
(let ((?x803 ((_ extract 31 4) encoded_capability32)))
(let ((?x804 (concat ?x803 (_ bv1 1) ?x802)))
(and (distinct ((_ extract 31 0) ((_ zero_extend 32) ?x804)) (bvor encoded_capability32 (_ bv8 32))) true)))))
(check-sat)
