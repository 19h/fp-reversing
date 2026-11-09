(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun word32 () (_ BitVec 32))
(assert
 (let ((?x9 (bvsub word32 (_ bv1765533448 32))))
(let ((?x13 (ite (bvsge ?x9 (_ bv0 32)) ?x9 (bvneg ?x9))))
(let ((?x55 (bvadd word32 (_ bv2529433848 32))))
(and (distinct (ite (bvsge ?x55 (_ bv0 32)) ?x55 (bvsub (_ bv1765533448 32) word32)) ?x13) true)))))
(check-sat)
