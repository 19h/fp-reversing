; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_sequence32 () (_ BitVec 32))
(declare-fun qs_message64 () (_ BitVec 64))
(assert
 (let (($x346 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv1 32) qs_sequence32))) (bvadd qs_sequence32 (_ bv1 32))) true)))
(let (($x344 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) qs_sequence32)) qs_sequence32) true)))
(let (($x17 (and (distinct qs_message64 qs_message64) true)))
(or (and (distinct (_ bv3746713848787403704 64) (_ bv3746713848787403704 64)) true) $x17 $x344 $x346)))))
(check-sat)
