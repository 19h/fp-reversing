; benchmark generated from python API
(set-info :status unknown)
(declare-fun ctxlock_logical_index64 () (_ BitVec 64))
(assert
 (let ((?x350 (bvmul ctxlock_logical_index64 (_ bv48 64))))
(let (($x351 (and (distinct (bvsub (bvmul (bvadd (_ bv2050650380 64) ctxlock_logical_index64) (_ bv48 64)) (_ bv98431218240 64)) ?x350) true)))
(and true $x351))))
(check-sat)
