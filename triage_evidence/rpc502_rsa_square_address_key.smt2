(set-option :timeout 60000)
; benchmark generated from python API
(set-info :status unknown)
(declare-fun argument_low32 () (_ BitVec 32))
(assert
 (let ((?x20 (bvadd (bvsub (bvshl (bvand argument_low32 (_ bv2092881279 32)) (_ bv1 32)) argument_low32) (_ bv54602368 32))))
(and (distinct (bvand (bvmul (bvxor ?x20 (_ bv2043899254 32)) (_ bv834057011 32)) (_ bv4294967295 32)) (bvmul (bvxor argument_low32 (_ bv2056407030 32)) (_ bv834057011 32))) true)))
(check-sat)
