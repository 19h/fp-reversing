; benchmark generated from python API
(set-info :status unknown)
(declare-fun fill64 () (_ BitVec 64))
(assert
 (and (distinct (bvmul ((_ zero_extend 32) ((_ extract 31 0) fill64)) (_ bv72340172838076673 64)) (bvmul ((_ zero_extend 32) ((_ extract 31 0) (bvadd fill64 (_ bv4294967296 64)))) (_ bv72340172838076673 64))) true))
(check-sat)
