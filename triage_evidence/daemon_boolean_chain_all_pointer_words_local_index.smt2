; benchmark generated from python API
(set-info :status unknown)
(declare-fun bool_chain_state_pointer64 () (_ BitVec 64))
(declare-fun bool_chain_decoded_tag32 () (_ BitVec 32))
(assert
 (let (($x113 (= bool_chain_state_pointer64 (_ bv0 64))))
(let ((?x33 (ite $x113 (_ bv46036 32) (_ bv46046 32))))
(let ((?x109 (ite $x113 (_ bv0 32) (_ bv1 32))))
(let ((?x19 (concat (_ bv0 1) ((_ extract 30 26) (bvadd (_ bv3552527331 32) bool_chain_decoded_tag32)) (_ bv0 1) ((_ extract 24 21) (bvadd (_ bv3552527331 32) bool_chain_decoded_tag32)) (_ bv0 1) ((_ extract 19 14) (bvadd (_ bv3552527331 32) bool_chain_decoded_tag32)) (_ bv0 2) ((_ extract 11 11) (bvadd (_ bv3552527331 32) bool_chain_decoded_tag32)) (_ bv0 1) ((_ extract 9 5) (bvadd (_ bv3552527331 32) bool_chain_decoded_tag32)) (_ bv0 1) ((_ extract 3 3) (bvadd (_ bv3552527331 32) bool_chain_decoded_tag32)) (_ bv0 1) ((_ extract 1 1) (bvadd (_ bv3552527331 32) bool_chain_decoded_tag32)) (_ bv0 1))))
(let ((?x71 (bvadd (_ bv2924493928 32) ?x19)))
(let ((?x75 (bvor bool_chain_decoded_tag32 (bvmul ?x71 ?x109))))
(let (($x57 (= bool_chain_decoded_tag32 (_ bv46036 32))))
(or (not (= ?x75 (bvor bool_chain_decoded_tag32 (ite $x113 (_ bv0 32) ?x71)))) (and $x57 (not (= ?x75 ?x33))))))))))))
(check-sat)
