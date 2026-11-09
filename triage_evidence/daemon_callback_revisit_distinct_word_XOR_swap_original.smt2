; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_swap_B64 () (_ BitVec 64))
(declare-fun callback_swap_A64 () (_ BitVec 64))
(assert
 (let ((?x427 (bvxor callback_swap_A64 callback_swap_B64)))
(let ((?x709 (bvxor ?x427 callback_swap_B64)))
(let (($x374 (or (and (distinct ?x709 callback_swap_A64) true) (and (distinct (bvxor ?x427 ?x709) callback_swap_B64) true))))
(and true $x374)))))
(check-sat)
