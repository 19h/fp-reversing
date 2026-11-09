; benchmark generated from python API
(set-info :status unknown)
(declare-fun operation32 () (_ BitVec 32))
(assert
 (let (($x241 (bvsle (_ bv7018 32) operation32)))
(let ((?x259 (ite $x241 (_ bv1 1) (_ bv0 1))))
(let ((?x255 (concat (_ bv85 28) ?x259 (_ bv7 3))))
(let ((?x244 ((_ zero_extend 32) ?x255)))
(let ((?x181 ((_ extract 31 0) ?x244)))
(let ((?x6 ((_ zero_extend 32) operation32)))
(let ((?x11 ((_ extract 31 0) ?x6)))
(let (($x13 (and (distinct ?x11 operation32) true)))
(or $x13 (and (distinct ((_ extract 31 0) ((_ zero_extend 32) (_ bv7018 32))) (_ bv7018 32)) true) (and (distinct ?x181 (ite (bvslt operation32 (_ bv7018 32)) (_ bv1367 32) (_ bv1375 32))) true)))))))))))
(check-sat)
