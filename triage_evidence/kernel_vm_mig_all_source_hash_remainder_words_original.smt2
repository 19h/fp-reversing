; benchmark generated from python API
(set-info :status unknown)
(declare-fun kmig_message_id32 () (_ BitVec 32))
(assert
 (let (($x71 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv1 32) kmig_message_id32))) (bvadd kmig_message_id32 (_ bv1 32))) true)))
(let ((?x58 (bvmul ((_ extract 31 0) (bvlshr (bvmul ((_ zero_extend 32) kmig_message_id32) (_ bv2132903255 64)) (_ bv41 64))) (_ bv1031 32))))
(let ((?x61 ((_ extract 63 41) (bvmul (_ bv2132903255 64) (concat (_ bv0 32) kmig_message_id32)))))
(let ((?x69 (concat (_ bv0 9) ?x61)))
(let ((?x77 (bvadd kmig_message_id32 (bvmul (_ bv4294966265 32) ?x69))))
(or (and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x77)) (bvsub kmig_message_id32 ?x58)) true) $x71)))))))
(check-sat)
