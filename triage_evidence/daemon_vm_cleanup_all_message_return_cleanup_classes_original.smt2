; benchmark generated from python API
(set-info :status unknown)
(declare-fun vmclean_trap_status32 () (_ BitVec 32))
(assert
 (let (($x398 (= vmclean_trap_status32 (_ bv268435472 32))))
(let (($x32 (= vmclean_trap_status32 (_ bv268435459 32))))
(let (($x428 (or (= vmclean_trap_status32 (_ bv268435458 32)) $x32 $x398)))
(let ((?x433 (bvshl (_ bv1 32) (concat (_ bv0 27) (bvadd (_ bv30 5) ((_ extract 4 0) vmclean_trap_status32))))))
(let ((?x411 ((_ extract 1 0) ?x433)))
(let ((?x420 ((_ extract 14 14) ?x433)))
(let ((?x396 ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4026531838 32) vmclean_trap_status32)))))
(let (($x389 (ite (or (not (bvuge ?x396 (_ bv14 32))) (= (bvsub ?x396 (_ bv14 32)) (_ bv0 32))) (= (bvsub ((_ extract 31 0) (concat (_ bv0 49) ?x420 (_ bv0 12) ?x411)) (_ bv0 32)) (_ bv0 32)) true)))
(and (distinct (not $x389) $x428) true))))))))))
(check-sat)
