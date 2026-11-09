; benchmark generated from python API
(set-info :status unknown)
(declare-fun bool_chain_phase32 () (_ BitVec 32))
(declare-fun bool_chain_key32 () (_ BitVec 32))
(assert
 (let ((?x36 (bvadd bool_chain_phase32 (_ bv3595409128 32))))
(and (distinct (bvxor (bvxor ?x36 bool_chain_key32) bool_chain_key32) ?x36) true)))
(check-sat)
