; benchmark generated from python API
(set-info :status unknown)
(declare-fun ctxlock_global64 () (_ BitVec 64))
(assert
 (let ((?x755 (bvadd ctxlock_global64 (_ bv8 64))))
(let ((?x815 (bvadd ?x755 (_ bv4 64))))
(let ((?x779 (bvadd ctxlock_global64 (_ bv16 64))))
(let (($x832 (and (bvult (bvadd ctxlock_global64 (_ bv0 64)) (bvadd ?x779 (_ bv8 64))) (bvult ?x779 (bvadd (bvadd ctxlock_global64 (_ bv0 64)) (_ bv8 64))))))
(let (($x811 (and (bvult (bvadd ctxlock_global64 (_ bv0 64)) ?x815) (bvult ?x755 (bvadd (bvadd ctxlock_global64 (_ bv0 64)) (_ bv8 64))))))
(let (($x901 (or $x811 $x832 (and (bvult ?x755 (bvadd ?x779 (_ bv8 64))) (bvult ?x779 ?x815)))))
(let (($x698 (bvule ctxlock_global64 (_ bv18446744073709551591 64))))
(and $x698 $x901)))))))))
(check-sat)
