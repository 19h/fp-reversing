; benchmark generated from python API
(set-info :status unknown)
(declare-fun input_W1 () (_ BitVec 32))
(declare-fun key32 () (_ BitVec 32))
(assert
 (let ((?x67 ((_ extract 15 0) (bvadd (bvadd key32 (bvmul (bvadd input_W1 (_ bv65536 32)) (_ bv32291 32))) (_ bv25802 32)))))
(and (distinct ((_ extract 15 0) (bvadd (bvadd key32 (bvmul input_W1 (_ bv32291 32))) (_ bv25802 32))) ?x67) true)))
(check-sat)
