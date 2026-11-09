; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_aux32 () (_ BitVec 32))
(declare-fun producer_selector32 () (_ BitVec 32))
(assert
 (let (($x254 (bvsle (_ bv4007463712 32) producer_aux32)))
(let ((?x231 (ite $x254 (_ bv0 32) (_ bv1 32))))
(let ((?x244 (concat (_ bv0 2) ((_ extract 29 29) (bvadd (_ bv3555211362 32) producer_selector32)) (_ bv0 1) ((_ extract 27 26) (bvadd (_ bv3555211362 32) producer_selector32)) (_ bv0 5) ((_ extract 20 20) (bvadd (_ bv3555211362 32) producer_selector32)) (_ bv0 1) ((_ extract 18 13) (bvadd (_ bv3555211362 32) producer_selector32)) (_ bv0 1) ((_ extract 11 11) (bvadd (_ bv3555211362 32) producer_selector32)) (_ bv0 2) ((_ extract 8 6) (bvadd (_ bv3555211362 32) producer_selector32)) (_ bv0 2) ((_ extract 3 3) (bvadd (_ bv3555211362 32) producer_selector32)) (_ bv0 1) (bvadd (_ bv2 2) ((_ extract 1 0) producer_selector32)))))
(let ((?x258 (bvadd (_ bv4294940355 32) ?x244)))
(let ((?x263 (bvadd (_ bv17464 32) producer_selector32)))
(let ((?x236 (bvxor ?x263 (bvmul ?x258 ?x231))))
(let ((?x240 ((_ extract 31 0) (concat (_ bv0 32) ?x236))))
(and (and (= producer_selector32 (_ bv18204 32)) (= producer_aux32 (_ bv736201309 32))) (and (distinct ?x240 (_ bv35668 32)) true))))))))))
(check-sat)
