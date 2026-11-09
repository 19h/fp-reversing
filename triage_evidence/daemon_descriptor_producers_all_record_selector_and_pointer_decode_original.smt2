; benchmark generated from python API
(set-info :status unknown)
(declare-fun producer_pointer64 () (_ BitVec 64))
(declare-fun producer_selector32 () (_ BitVec 32))
(assert
 (let (($x80 (and (distinct producer_pointer64 producer_pointer64) true)))
(let (($x136 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) producer_selector32)) producer_selector32) true)))
(and true (or $x136 $x80)))))
(check-sat)
