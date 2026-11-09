; benchmark generated from python API
(set-info :status unknown)
(declare-fun destruct_counter64 () (_ BitVec 64))
(assert
 (let ((?x1329 (bvmul (bvxor (bvadd (bvadd ((_ extract 31 0) destruct_counter64) (_ bv256 32)) (_ bv110 32)) (_ bv186 32)) (bvadd (bvadd ((_ extract 31 0) destruct_counter64) (_ bv256 32)) (_ bv127 32)))))
(let ((?x489 (bvmul (bvxor (bvadd ((_ extract 31 0) destruct_counter64) (_ bv110 32)) (_ bv186 32)) (bvadd ((_ extract 31 0) destruct_counter64) (_ bv127 32)))))
(let ((?x653 ((_ extract 7 0) ?x489)))
(and true (and (distinct ?x653 ((_ extract 7 0) ?x1329)) true))))))
(check-sat)
