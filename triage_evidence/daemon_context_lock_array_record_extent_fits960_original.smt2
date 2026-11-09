; benchmark generated from python API
(set-info :status unknown)
(declare-fun ctxlock_logical_index64 () (_ BitVec 64))
(assert
 (let ((?x350 (bvmul ctxlock_logical_index64 (_ bv48 64))))
(let ((?x379 (bvadd ?x350 (_ bv48 64))))
(let (($x396 (bvule ctxlock_logical_index64 (_ bv19 64))))
(and $x396 (or (bvugt ?x379 (_ bv960 64)) (bvult ?x379 ?x350)))))))
(check-sat)
