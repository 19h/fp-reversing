; benchmark generated from python API
(set-info :status unknown)
(declare-fun fields_byte8 () (_ BitVec 8))
(assert
 (let ((?x69 (concat (_ bv16691191 24) ((_ extract 7 7) fields_byte8) (bvnot ((_ extract 6 5) fields_byte8)) ((_ extract 4 4) fields_byte8) (bvnot ((_ extract 3 1) fields_byte8)) ((_ extract 0 0) fields_byte8))))
(let ((?x126 ((_ extract 3 1) fields_byte8)))
(let ((?x122 ((_ extract 6 5) fields_byte8)))
(let ((?x90 (concat (_ bv0 24) ?x122 (_ bv0 1) ?x126 (_ bv0 2))))
(and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv1138490870 32) ?x90 ?x69))) (bvadd ((_ zero_extend 24) fields_byte8) (_ bv1116468580 32))) true))))))
(check-sat)
