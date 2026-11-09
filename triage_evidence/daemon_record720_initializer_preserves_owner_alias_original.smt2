; benchmark generated from python API
(set-info :status unknown)
(declare-fun record720_pointer64 () (_ BitVec 64))
(assert
 (let (($x80 (and (distinct record720_pointer64 record720_pointer64) true)))
(let (($x478 (or (bvule (bvadd record720_pointer64 (_ bv720 64)) (_ bv446676664320 64)) (bvuge record720_pointer64 (_ bv446676729856 64)))))
(let (($x473 (bvule record720_pointer64 (_ bv18446744073709550895 64))))
(let (($x479 (and $x473 $x478)))
(and $x479 (or $x80 $x80)))))))
(check-sat)
