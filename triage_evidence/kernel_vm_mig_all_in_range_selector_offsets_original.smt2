; benchmark generated from python API
(set-info :status unknown)
(declare-fun kmig_message_id32 () (_ BitVec 32))
(assert
 (let ((?x13 ((_ sign_extend 32) ((_ extract 31 0) (bvadd (_ bv18446744073709398024 64) (concat (_ bv0 27) kmig_message_id32 (_ bv0 5)))))))
(let ((?x53 (concat (_ bv0 27) kmig_message_id32 (_ bv0 5))))
(let ((?x54 (bvadd (_ bv18446744073709398024 64) ?x53)))
(let (($x30 (and (distinct ?x54 (bvadd (bvmul ((_ zero_extend 32) (bvsub kmig_message_id32 (_ bv4800 32))) (_ bv32 64)) (_ bv8 64))) true)))
(let (($x34 (and (bvuge kmig_message_id32 (_ bv4800 32)) (bvult kmig_message_id32 (_ bv4830 32)))))
(and $x34 (or $x30 (and (distinct (_ bv18446741874818842792 64) (_ bv18446741874818842792 64)) true) (and (distinct ?x54 ?x13) true)))))))))
(check-sat)
