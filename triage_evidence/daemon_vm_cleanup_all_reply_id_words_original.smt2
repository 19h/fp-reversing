; benchmark generated from python API
(set-info :status unknown)
(declare-fun vmclean_reply_id32 () (_ BitVec 32))
(assert
 (let (($x466 (= vmclean_reply_id32 (_ bv4901 32))))
(let ((?x394 (bvsub ((_ extract 31 0) ((_ zero_extend 32) ((_ extract 31 0) (concat (_ bv0 32) vmclean_reply_id32)))) ((_ extract 31 0) (_ bv4901 64)))))
(let (($x464 (= vmclean_reply_id32 (_ bv71 32))))
(let (($x463 (and (distinct (= (bvsub ((_ extract 31 0) (concat (_ bv0 32) vmclean_reply_id32)) (_ bv71 32)) (_ bv0 32)) $x464) true)))
(or $x463 (and (distinct (= ?x394 (_ bv0 32)) $x466) true)))))))
(check-sat)
