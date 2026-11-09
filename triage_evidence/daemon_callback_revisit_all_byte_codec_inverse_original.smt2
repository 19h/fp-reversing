; benchmark generated from python API
(set-info :status unknown)
(declare-fun callback_byte8 () (_ BitVec 8))
(declare-fun callback_seed32 () (_ BitVec 32))
(declare-fun callback_index32 () (_ BitVec 32))
(assert
 (let ((?x455 (bvmul (bvadd callback_index32 callback_seed32) (bvsub callback_index32 callback_seed32))))
(let ((?x422 ((_ extract 7 0) (bvxor callback_seed32 ?x455))))
(let (($x572 (and (distinct (bvxor (bvmul (bvmul (bvxor callback_byte8 ?x422) (_ bv147 8)) (_ bv155 8)) ?x422) callback_byte8) true)))
(and true $x572)))))
(check-sat)
