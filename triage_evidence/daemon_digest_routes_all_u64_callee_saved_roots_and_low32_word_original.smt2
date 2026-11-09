; benchmark generated from python API
(set-info :status unknown)
(declare-fun routes_input64 () (_ BitVec 64))
(declare-fun routes_return64 () (_ BitVec 64))
(declare-fun routes_context64 () (_ BitVec 64))
(declare-fun routes_A64 () (_ BitVec 64))
(assert
 (let (($x257 (and (distinct routes_input64 routes_input64) true)))
(let (($x54 (and (distinct routes_context64 routes_context64) true)))
(let (($x308 (and (distinct routes_A64 routes_A64) true)))
(or $x308 $x54 (and (distinct ((_ extract 31 0) routes_return64) ((_ extract 31 0) routes_return64)) true) $x257 (and (distinct ((_ extract 31 0) (_ bv0 64)) (_ bv0 32)) true))))))
(check-sat)
