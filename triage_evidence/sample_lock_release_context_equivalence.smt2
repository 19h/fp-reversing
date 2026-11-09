; benchmark generated from python API
(set-info :status unknown)
(declare-fun first_context_state32 () (_ BitVec 32))
(assert
 (let ((?x77 (bvadd first_context_state32 (_ bv579 32))))
(let ((?x87 (bvadd ?x77 (_ bv1248 32))))
(let ((?x85 (bvadd first_context_state32 (_ bv1827 32))))
(and (distinct ?x85 ?x87) true)))))
(check-sat)
