; benchmark generated from python API
(set-info :status unknown)
(declare-fun release_index32 () (_ BitVec 32))
(declare-fun release_input64 () (_ BitVec 64))
(assert
 (let (($x569 (and (distinct ((_ extract 31 0) (_ bv32977 64)) (_ bv32977 32)) true)))
(let (($x535 (and (distinct release_input64 release_input64) true)))
(let (($x583 (or $x535 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) release_index32)) release_index32) true) $x569 (and (distinct ((_ extract 31 0) (_ bv47825 64)) (_ bv47825 32)) true))))
(and true $x583)))))
(check-sat)
