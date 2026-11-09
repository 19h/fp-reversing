(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun argument_low32 () (_ BitVec 32))
(assert
 (let ((?x36 (bvadd (bvsub (bvor argument_low32 (_ bv2681534773 32)) argument_low32) (bvand argument_low32 (_ bv1613432522 32)))))
(and (distinct (bvand (bvmul (bvxor (bvand ?x36 (_ bv4294967295 32)) (_ bv163225895 32)) (_ bv1496199031 32)) (_ bv4294967295 32)) (bvmul (bvxor argument_low32 (_ bv2523813906 32)) (_ bv1496199031 32))) true)))
(check-sat)
