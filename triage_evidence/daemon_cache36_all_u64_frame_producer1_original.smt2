; benchmark generated from python API
(set-info :status unknown)
(declare-fun cache36_cursor64 () (_ BitVec 64))
(assert
 (let ((?x56 (bvadd (_ bv446676976880 64) cache36_cursor64)))
(let ((?x95 (bvadd (_ bv446676975728 64) cache36_cursor64)))
(or (and (distinct ?x95 ?x95) true) (and (distinct ?x56 ?x56) true)))))
(check-sat)
