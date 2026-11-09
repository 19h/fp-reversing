; benchmark generated from python API
(set-info :status unknown)
(assert
 (let ((?x236 ((_ extract 31 0) (_ bv18204 64))))
(let (($x245 (and (distinct ?x236 (_ bv18204 32)) true)))
(let (($x211 (and (distinct (_ bv4311981808 64) (_ bv4311981808 64)) true)))
(and true (or (and (distinct ((_ extract 31 0) (_ bv50695 64)) (_ bv50695 32)) true) $x211 $x245))))))
(check-sat)
