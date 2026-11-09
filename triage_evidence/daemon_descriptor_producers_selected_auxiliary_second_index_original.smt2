; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_aux32 () (_ BitVec 32))
(assert
 (let ((?x319 (bvmul (_ bv2 9) (ite (bvsle (_ bv736201309 32) producer_aux32) (_ bv0 9) (_ bv1 9)))))
(let ((?x308 (bvnot ((_ extract 9 9) (bvmul (_ bv2 32) (ite (bvsle (_ bv736201309 32) producer_aux32) (_ bv0 32) (_ bv1 32)))))))
(let ((?x297 (bvmul (_ bv2 32) (ite (bvsle (_ bv736201309 32) producer_aux32) (_ bv0 32) (_ bv1 32)))))
(let ((?x301 ((_ extract 14 10) ?x297)))
(let ((?x306 (bvnot ((_ extract 15 15) ?x297))))
(let ((?x303 ((_ extract 31 16) ?x297)))
(let (($x287 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x303 ?x306 ?x301 ?x308 ?x319)) (ite (bvsgt (_ bv736201309 32) producer_aux32) (_ bv33282 32) (_ bv33280 32))) true)))
(and true $x287)))))))))
(check-sat)
