; benchmark generated from python API
(set-info :status unknown)
(declare-fun release_control32 () (_ BitVec 32))
(declare-fun release_pointer64 () (_ BitVec 64))
(assert
 (let (($x63 (and (distinct ((_ extract 31 0) (concat (_ bv0 32) (bvadd (_ bv417838532 32) release_control32))) (bvsub (bvadd release_control32 (_ bv29847 32)) (bvmul (bvxor (_ bv188048 32) (_ bv3050994369 32)) (_ bv1575132131 32)))) true)))
(let (($x122 (and (distinct release_pointer64 release_pointer64) true)))
(and true (or $x122 $x63)))))
(check-sat)
