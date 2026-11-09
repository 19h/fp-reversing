; benchmark generated from python API
(set-info :status unknown)
(declare-fun qs_sequence32 () (_ BitVec 32))
(declare-fun qs_aux_size32 () (_ BitVec 32))
(declare-fun qs_user_message_size32 () (_ BitVec 32))
(assert
 (let (($x344 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) qs_sequence32)) qs_sequence32) true)))
(let ((?x476 ((_ extract 15 0) qs_aux_size32)))
(let ((?x459 ((_ zero_extend 16) ?x476)))
(let (($x509 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) qs_user_message_size32)) qs_user_message_size32) true)))
(or $x509 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) ?x459)) ?x459) true) (and (distinct ((_ extract 31 0) (_ bv268451844 64)) (_ bv268451844 32)) true) $x344 (and (distinct (_ bv0 64) (_ bv0 64)) true) (and (distinct (_ bv0 32) (_ bv0 32)) true)))))))
(check-sat)
