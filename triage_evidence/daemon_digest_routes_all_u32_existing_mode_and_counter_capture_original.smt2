; benchmark generated from python API
(set-info :status unknown)
(declare-fun routes_value32 () (_ BitVec 32))
(declare-fun routes_phase32 () (_ BitVec 32))
(assert
 (let (($x110 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv24136 32) routes_phase32))) (bvadd routes_phase32 (_ bv24136 32))) true)))
(or $x110 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) routes_value32)) routes_value32) true))))
(check-sat)
