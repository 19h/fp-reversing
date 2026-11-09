; benchmark generated from python API
(set-info :status unknown)
(declare-fun first_context_state32 () (_ BitVec 32))
(assert
 (let ((?x77 (bvadd first_context_state32 (_ bv579 32))))
(let ((?x83 (bvsub ?x77 (_ bv42 32))))
(let ((?x81 (bvadd first_context_state32 (_ bv537 32))))
(and (distinct ?x81 ?x83) true)))))
(check-sat)
