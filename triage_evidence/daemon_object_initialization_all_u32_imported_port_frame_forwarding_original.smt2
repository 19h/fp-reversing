; benchmark generated from python API
(set-info :status unknown)
(declare-fun init_port32 () (_ BitVec 32))
(assert
 (let (($x1546 (or (and (distinct (concat (_ bv0 32) init_port32) ((_ zero_extend 32) init_port32)) true) (and (distinct ((_ extract 31 0) (concat (_ bv0 32) init_port32)) init_port32) true))))
(and true $x1546)))
(check-sat)
