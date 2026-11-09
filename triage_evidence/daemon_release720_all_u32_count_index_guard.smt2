; benchmark generated from python API
(set-info :status unknown)
(declare-fun release_count32 () (_ BitVec 32))
(declare-fun release_index32 () (_ BitVec 32))
(assert
 (let (($x438 (and (= ((_ extract 31 31) release_index32) (_ bv0 1)) (bvule ((_ extract 30 0) release_index32) (_ bv1817892310 31)))))
(let (($x530 (or $x438 (= release_index32 (_ bv4294967295 32)))))
(let (($x442 (and (= ((_ extract 31 31) release_count32) (_ bv0 1)) (bvule ((_ extract 30 0) release_count32) (_ bv1817892311 31)))))
(let (($x543 (= (bvxor (ite $x442 (_ bv0 32) (_ bv1 32)) (ite $x530 (_ bv0 32) (_ bv1 32))) (_ bv0 32))))
(let (($x546 (and $x543 (bvule (bvadd (_ bv2477074984 32) release_count32) (bvadd (_ bv2477074985 32) release_index32)) (not (= release_index32 (bvadd (_ bv4294967295 32) release_count32))))))
(let ((?x403 (bvmul (_ bv53 32) (concat (_ bv0 31) (ite (or $x546 (and (not $x543) (not $x530))) (_ bv0 1) (_ bv1 1))))))
(let (($x735 (= ?x403 (ite (bvule (bvadd (_ bv1 32) release_index32) release_count32) (_ bv53 32) (_ bv0 32)))))
(not $x735)))))))))
(check-sat)
