; benchmark generated from python API
(set-info :status unknown)
(declare-fun decoder_entry_W28 () (_ BitVec 32))
(assert
 (let ((?x44 ((_ extract 0 0) decoder_entry_W28)))
(let ((?x45 (bvnot ?x44)))
(let ((?x34 ((_ extract 4 1) decoder_entry_W28)))
(let ((?x43 (bvnot ((_ extract 9 5) decoder_entry_W28))))
(let ((?x36 ((_ extract 13 10) decoder_entry_W28)))
(let ((?x41 (bvnot ((_ extract 15 14) decoder_entry_W28))))
(let ((?x38 ((_ extract 31 16) decoder_entry_W28)))
(let ((?x46 (concat ?x38 ?x41 ?x36 ?x43 ?x34 ?x45)))
(and (distinct ((_ extract 31 0) ((_ zero_extend 32) ?x46)) (bvxor decoder_entry_W28 (_ bv50145 32))) true))))))))))
(check-sat)
