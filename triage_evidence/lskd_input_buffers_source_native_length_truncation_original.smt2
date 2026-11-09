; benchmark generated from python API
(set-info :status unknown)
(declare-fun native_random_length64 () (_ BitVec 64))
(assert
 (let ((?x104 ((_ extract 31 0) native_random_length64)))
(let ((?x152 ((_ zero_extend 32) ?x104)))
(and (distinct ?x152 ?x152) true))))
(check-sat)
