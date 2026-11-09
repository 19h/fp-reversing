; benchmark generated from python API
(set-info :status unknown)
(declare-fun reader_phase32 () (_ BitVec 32))
(assert
 (let ((?x190 ((_ extract 0 0) reader_phase32)))
(let ((?x182 (bvadd (_ bv4294951136 32) reader_phase32)))
(let ((?x185 ((_ extract 8 3) ?x182)))
(let ((?x186 ((_ extract 10 10) ?x182)))
(let ((?x187 ((_ extract 31 15) ?x182)))
(let (($x184 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) ?x187 (_ bv15 4) ?x186 (_ bv1 1) ?x185 (_ bv3 2) ?x190)) (bvor (bvsub reader_phase32 (_ bv16160 32)) (_ bv31238 32))) true)))
(and true $x184))))))))
(check-sat)
