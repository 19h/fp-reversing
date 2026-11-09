; benchmark generated from python API
(set-info :status unknown)
(declare-fun ctxlock_logical_index64 () (_ BitVec 64))
(assert
 (let (($x286 (bvule (bvadd (_ bv48 10) (bvmul (_ bv48 10) ((_ extract 9 0) ctxlock_logical_index64))) (_ bv960 10))))
(let (($x542 (and (= ((_ extract 63 10) (bvadd (_ bv48 64) (bvmul (_ bv48 64) ctxlock_logical_index64))) (_ bv0 54)) $x286)))
(let ((?x410 (bvmul (_ bv48 64) ctxlock_logical_index64)))
(let ((?x290 (bvadd (_ bv48 64) ?x410)))
(let (($x6 (or (not (bvule ?x410 ?x290)) (not $x542))))
(let (($x291 (bvule ((_ extract 4 0) ctxlock_logical_index64) (_ bv19 5))))
(let (($x240 (= ((_ extract 63 5) ctxlock_logical_index64) (_ bv0 59))))
(and $x240 $x291 $x6)))))))))
(check-sat)
