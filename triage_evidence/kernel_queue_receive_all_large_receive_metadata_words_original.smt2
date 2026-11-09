; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_aux_extent16 () (_ BitVec 16))
(declare-fun qr_message_extent32 () (_ BitVec 32))
(declare-fun qr_receiver_name32 () (_ BitVec 32))
(assert
 (let ((?x48 ((_ zero_extend 16) qr_aux_extent16)))
(let ((?x101 ((_ extract 31 0) ((_ zero_extend 32) ?x48))))
(let (($x100 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) qr_message_extent32)) qr_message_extent32) true)))
(let (($x109 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) qr_receiver_name32)) qr_receiver_name32) true)))
(or $x109 (and (distinct (_ bv0 64) (_ bv0 64)) true) $x100 (and (distinct ?x101 ?x48) true)))))))
(check-sat)
