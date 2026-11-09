; benchmark generated from python API
(set-info :status unknown)
(declare-fun consumer_lookup_t32 () (_ BitVec 32))
(declare-fun consumer_update_x32 () (_ BitVec 32))
(assert
 (let ((?x944 (bvnot consumer_lookup_t32)))
(let ((?x945 (bvshl ?x944 (_ bv16 32))))
(let ((?x946 (bvor consumer_update_x32 ?x945)))
(and true (and (distinct (bvor ?x946 ?x945) ?x946) true))))))
(check-sat)
