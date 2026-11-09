; benchmark generated from python API
(set-info :status unknown)
(declare-fun fallback_version32 () (_ BitVec 32))
(assert
 (let (($x257 (bvule (_ bv773718016 30) ((_ extract 29 0) fallback_version32))))
(let (($x647 (not (= ((_ extract 31 30) fallback_version32) (_ bv0 2)))))
(let (($x1058 (or $x647 $x257)))
(let (($x252 (not $x1058)))
(let (($x1372 (bvule (_ bv11806 14) ((_ extract 29 16) fallback_version32))))
(let (($x1134 (or $x647 $x1372)))
(let (($x1318 (and (or $x1134 $x1058 (= (_ bv3298203632 32) (_ bv3298203632 32))) (or (not $x1134) $x252 (= (_ bv3298203640 32) (_ bv3298203640 32))) (or (not $x1134) $x1058 (= (_ bv3298203640 32) (_ bv3298203632 32))) (or $x1134 $x252 (= (_ bv3298203632 32) (_ bv3298203640 32))))))
(not $x1318)))))))))
(check-sat)
