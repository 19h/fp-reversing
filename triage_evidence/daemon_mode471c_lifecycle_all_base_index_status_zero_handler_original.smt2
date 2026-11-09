; benchmark generated from python API
(set-info :status unknown)
(declare-fun life_index32 () (_ BitVec 32))
(declare-fun life_base64 () (_ BitVec 64))
(declare-fun life_status32 () (_ BitVec 32))
(assert
 (let (($x287 (= (_ bv2336081489 32) life_status32)))
(let ((?x301 (ite $x287 (bvadd life_base64 (bvshl ((_ zero_extend 32) life_index32) (_ bv5 64))) (_ bv0 64))))
(let (($x54 (= life_status32 (_ bv2336081489 32))))
(let (($x303 (and (distinct (ite $x54 (bvadd life_base64 (concat (_ bv0 27) life_index32 (_ bv0 5))) (_ bv0 64)) ?x301) true)))
(let ((?x314 (concat (_ bv0 32) (ite $x54 (ite (= life_base64 (_ bv0 64)) (_ bv1958911796 32) (_ bv2336081489 32)) life_status32))))
(let (($x313 (and (distinct ((_ extract 31 0) ?x314) (ite $x287 (ite (= life_base64 (_ bv0 64)) (_ bv1958911796 32) (_ bv2336081489 32)) life_status32)) true)))
(and true (or $x313 $x303)))))))))
(check-sat)
