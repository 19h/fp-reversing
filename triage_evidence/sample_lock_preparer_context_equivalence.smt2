; benchmark generated from python API
(set-info :status unknown)
(declare-fun first_context_state32 () (_ BitVec 32))
(assert
 (let ((?x77 (bvadd first_context_state32 (_ bv579 32))))
(let ((?x79 (bvadd ?x77 (_ bv692 32))))
(let ((?x75 (bvadd first_context_state32 (_ bv1271 32))))
(and (distinct ?x75 ?x79) true)))))
(check-sat)
