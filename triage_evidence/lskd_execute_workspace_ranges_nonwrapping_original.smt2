; benchmark generated from python API
(set-info :status unknown)
(declare-fun workspace64 () (_ BitVec 64))
(assert
 (let (($x212 (or (bvugt (bvadd (_ bv64 64) workspace64) (bvadd (_ bv16384 64) workspace64)) (bvugt (bvadd (_ bv128 64) workspace64) (bvadd workspace64 (_ bv16384 64))))))
(let (($x207 (bvule workspace64 (_ bv18446744073709535231 64))))
(and $x207 $x212))))
(check-sat)
