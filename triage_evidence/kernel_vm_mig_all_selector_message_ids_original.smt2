; benchmark generated from python API
(set-info :status unknown)
(declare-fun kmig_message_id32 () (_ BitVec 32))
(assert
 (let (($x34 (and (bvuge kmig_message_id32 (_ bv4800 32)) (bvult kmig_message_id32 (_ bv4830 32)))))
(let ((?x25 (bvadd ((_ zero_extend 1) ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4294962466 32) kmig_message_id32)))) ((_ zero_extend 1) (_ bv30 32)))))
(and (distinct (= ((_ extract 32 32) ?x25) (_ bv1 1)) $x34) true))))
(check-sat)
