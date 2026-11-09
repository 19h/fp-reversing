; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_return64 () (_ BitVec 64))
(assert
 (let (($x2054 (or (and (distinct init_return64 init_return64) true) (and (distinct ((_ extract 31 0) (_ bv44 64)) (_ bv44 32)) true) (and (distinct ((_ extract 31 0) (_ bv2336081476 64)) (_ bv2336081476 32)) true) (and (distinct ((_ extract 31 0) (_ bv2336081473 64)) (_ bv2336081473 32)) true) (and (distinct ((_ extract 31 0) (_ bv32 64)) (_ bv32 32)) true) (and (distinct (_ bv446676620024 64) (_ bv446676620024 64)) true))))
(and true $x2054)))
(check-sat)
