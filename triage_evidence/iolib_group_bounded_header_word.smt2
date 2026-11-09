; benchmark generated from python API
(set-info :status unknown)
(declare-fun flags32 () (_ BitVec 32))
(declare-fun registry_token16 () (_ BitVec 16))
(assert
 (let (($x31 (and (distinct (bvand (bvor ((_ zero_extend 16) registry_token16) flags32) (_ bv2147483648 32)) (_ bv0 32)) true)))
(let (($x28 (and (distinct (bvand (bvor ((_ zero_extend 16) registry_token16) flags32) (_ bv196608 32)) flags32) true)))
(let ((?x8 ((_ zero_extend 16) registry_token16)))
(and (= (bvand flags32 (_ bv4294770687 32)) (_ bv0 32)) (or (and (distinct (bvand (bvor ?x8 flags32) (_ bv65535 32)) ?x8) true) $x28 $x31))))))
(check-sat)
