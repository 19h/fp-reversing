; benchmark generated from python API
(set-info :status unknown)
(declare-fun read_return64 () (_ BitVec 64))
(assert
 (let ((?x22 ((_ extract 31 0) read_return64)))
(let (($x24 (= ?x22 (_ bv4 32))))
(and (distinct $x24 (= (bvand read_return64 (_ bv4294967295 64)) (_ bv4 64))) true))))
(check-sat)
