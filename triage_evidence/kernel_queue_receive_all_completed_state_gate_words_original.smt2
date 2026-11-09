; benchmark generated from python API
(set-info :status unknown)
(declare-fun qr_completed_state32 () (_ BitVec 32))
(assert
 (let (($x89 (= qr_completed_state32 (_ bv0 32))))
(let (($x85 (or $x89 (= qr_completed_state32 (_ bv268451844 32)) (= qr_completed_state32 (_ bv268451854 32)))))
(let (($x682 (= (bvsub ((_ extract 31 0) ((_ zero_extend 32) qr_completed_state32)) ((_ extract 31 0) (_ bv268451854 64))) (_ bv0 32))))
(let (($x672 (= (bvsub ((_ extract 31 0) ((_ zero_extend 32) qr_completed_state32)) ((_ extract 31 0) (_ bv268451844 64))) (_ bv0 32))))
(and (distinct (or $x89 $x672 $x682) $x85) true))))))
(check-sat)
