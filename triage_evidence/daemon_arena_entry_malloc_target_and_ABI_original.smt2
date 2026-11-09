; benchmark generated from python API
(set-info :status unknown)
(declare-fun arena_frame64 () (_ BitVec 64))
(declare-fun malloc_code_pointer64 () (_ BitVec 64))
(assert
 (let (($x141 (and (distinct (_ bv27300 64) (_ bv27300 64)) true)))
(let (($x130 (and (distinct malloc_code_pointer64 malloc_code_pointer64) true)))
(or $x130 $x141 (and (distinct ((_ zero_extend 32) (_ bv90000 32)) (_ bv90000 64)) true) (and (distinct arena_frame64 arena_frame64) true)))))
(check-sat)
