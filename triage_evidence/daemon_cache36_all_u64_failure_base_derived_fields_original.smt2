; benchmark generated from python API
(set-info :status unknown)
(declare-fun cache36_return64 () (_ BitVec 64))
(assert
 (let (($x115 (and (distinct (bvadd (_ bv228 64) cache36_return64) (bvadd cache36_return64 (_ bv228 64))) true)))
(let (($x110 (and (distinct (bvadd (_ bv527 64) cache36_return64) (bvadd cache36_return64 (_ bv527 64))) true)))
(let (($x74 (and (distinct (bvadd (_ bv284 64) cache36_return64) (bvadd cache36_return64 (_ bv284 64))) true)))
(let (($x94 (and (distinct (bvadd (_ bv812 64) cache36_return64) (bvadd cache36_return64 (_ bv812 64))) true)))
(or $x94 $x74 $x110 (and (distinct cache36_return64 (bvadd cache36_return64 (_ bv0 64))) true) $x115))))))
(check-sat)
