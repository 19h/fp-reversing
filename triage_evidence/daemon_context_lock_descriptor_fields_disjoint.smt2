; benchmark generated from python API
(set-info :status unknown)
(declare-fun ctxlock_global64 () (_ BitVec 64))
(assert
 (let (($x974 (not (bvule (bvadd (_ bv8 64) ctxlock_global64) (bvadd (_ bv16 64) ctxlock_global64)))))
(let (($x1838 (and (not (bvule (bvadd (_ bv24 64) ctxlock_global64) ctxlock_global64)) $x974)))
(let (($x1089 (not (bvule (bvadd (_ bv12 64) ctxlock_global64) (bvadd (_ bv16 64) ctxlock_global64)))))
(let (($x360 (not (bvule (bvadd (_ bv24 64) ctxlock_global64) (bvadd (_ bv8 64) ctxlock_global64)))))
(let (($x977 (or (and $x360 $x1089) $x1838)))
(let (($x698 (bvule ctxlock_global64 (_ bv18446744073709551591 64))))
(and $x698 $x977))))))))
(check-sat)
