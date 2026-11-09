; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_sent_counter64 () (_ BitVec 64))
(assert
 (let ((?x564 (bvadd qs_sent_counter64 (_ bv1 64))))
(or (and (distinct ?x564 ?x564) true) (and (distinct qs_sent_counter64 qs_sent_counter64) true))))
(check-sat)
