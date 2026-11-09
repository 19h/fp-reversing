; benchmark generated from python API
(set-info :status unknown)
(declare-fun fields_byte8 () (_ BitVec 8))
(assert
 (let ((?x238 ((_ extract 4 3) fields_byte8)))
(let ((?x240 (concat (_ bv0 26) ?x238 (_ bv0 4))))
(let ((?x111 (bvmul (_ bv4294967295 32) ?x240)))
(let ((?x202 (concat (_ bv0 24) fields_byte8)))
(and (distinct ((_ extract 7 0) ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv4294967192 32) ?x202 ?x111)))) (bvxor fields_byte8 (_ bv152 8))) true))))))
(check-sat)
