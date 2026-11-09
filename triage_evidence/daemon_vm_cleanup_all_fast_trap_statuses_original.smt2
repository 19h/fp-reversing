; benchmark generated from python API
(set-info :status unknown)
(declare-fun vmclean_trap_status32 () (_ BitVec 32))
(assert
 (let (($x32 (= vmclean_trap_status32 (_ bv268435459 32))))
(let (($x18 (= (bvsub ((_ extract 31 0) ((_ zero_extend 32) vmclean_trap_status32)) ((_ extract 31 0) (_ bv268435459 64))) (_ bv0 32))))
(and (distinct $x18 $x32) true))))
(check-sat)
