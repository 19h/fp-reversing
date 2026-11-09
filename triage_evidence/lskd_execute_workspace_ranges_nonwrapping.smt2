; benchmark generated from python API
(set-info :status unknown)
(declare-fun workspace64 () (_ BitVec 64))
(assert
 (let (($x321 (not (bvule (bvadd (_ bv128 64) workspace64) (bvadd (_ bv16384 64) workspace64)))))
(let (($x262 (not (bvule (bvadd (_ bv64 64) workspace64) (bvadd (_ bv16384 64) workspace64)))))
(let (($x201 (or $x262 $x321)))
(let (($x207 (bvule workspace64 (_ bv18446744073709535231 64))))
(and $x207 $x201))))))
(check-sat)
