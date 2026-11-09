; benchmark generated from python API
(set-info :status unknown)
(declare-fun destruct_expected32 () (_ BitVec 32))
(declare-fun destruct_header32 () (_ BitVec 32))
(assert
 (let (($x114 (= destruct_header32 destruct_expected32)))
(let (($x100 (= ((_ extract 31 0) (concat (_ bv0 32) destruct_header32)) ((_ extract 31 0) ((_ zero_extend 32) destruct_expected32)))))
(and true (and (distinct $x100 $x114) true)))))
(check-sat)
