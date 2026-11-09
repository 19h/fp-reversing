; benchmark generated from python API
(set-info :status unknown)
(declare-fun shared_core_loaded_word_delta64 () (_ BitVec 64))
(assert
 (let ((?x178 (bvadd (_ bv4311948960 64) shared_core_loaded_word_delta64)))
(let ((?x70 (bvadd (_ bv4311499056 64) shared_core_loaded_word_delta64)))
(or (and (distinct ?x70 ?x70) true) (and (distinct ?x178 ?x178) true)))))
(check-sat)
