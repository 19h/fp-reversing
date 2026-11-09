; benchmark generated from python API
(set-info :status unknown)
(declare-fun handoff_status32 () (_ BitVec 32))
(assert
 (let (($x451 (= handoff_status32 (_ bv2336081489 32))))
(let ((?x448 (ite $x451 (_ bv23429 32) (_ bv23431 32))))
(let ((?x457 (bvmul (_ bv2 32) (ite $x451 (_ bv0 32) (_ bv1 32)))))
(let ((?x449 ((_ extract 1 1) ?x457)))
(let ((?x456 ((_ extract 6 3) ?x457)))
(let ((?x459 ((_ extract 10 10) ?x457)))
(let ((?x460 ((_ extract 13 13) ?x457)))
(let ((?x461 ((_ extract 31 15) ?x457)))
(not (= (concat ?x461 (_ bv1 1) ?x460 (_ bv3 2) ?x459 (_ bv7 3) ?x456 (_ bv1 1) ?x449 (_ bv1 1)) ?x448)))))))))))
(check-sat)
