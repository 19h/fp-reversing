; benchmark generated from python API
(set-info :status unknown)
(declare-fun consumer_signed_byte8 () (_ BitVec 8))
(assert
 (let ((?x14 ((_ extract 7 7) consumer_signed_byte8)))
(let ((?x51 (concat (_ bv0 32) ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 ?x14 consumer_signed_byte8)))
(and (distinct ?x51 ((_ zero_extend 32) ((_ sign_extend 24) consumer_signed_byte8))) true))))
(check-sat)
