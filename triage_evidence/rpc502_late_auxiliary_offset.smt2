(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun dispatch_seed32 () (_ BitVec 32))
(declare-fun saved_status32 () (_ BitVec 32))
(declare-fun auxiliary32 () (_ BitVec 32))
(assert
 (let ((?x14 (bvadd (bvxor (bvadd dispatch_seed32 (_ bv33716 32)) (_ bv2336040421 32)) dispatch_seed32)))
(let ((?x22 (bvsub (bvadd (bvadd auxiliary32 dispatch_seed32) (_ bv3583953950 32)) (ite (= saved_status32 ?x14) (_ bv1 32) (_ bv0 32)))))
(let ((?x184 (bvnot (bvor (bvsub saved_status32 ?x14) (bvsub ?x14 saved_status32)))))
(let ((?x15 (bvadd auxiliary32 dispatch_seed32)))
(and (distinct (bvadd (bvadd ?x15 (bvashr ?x184 (_ bv31 32))) (_ bv3583953950 32)) ?x22) true))))))
(check-sat)
