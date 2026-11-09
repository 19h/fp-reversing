; benchmark generated from python API
(set-info :status unknown)
(declare-fun fields_expected8 () (_ BitVec 8))
(declare-fun fields_byte8 () (_ BitVec 8))
(assert
 (let ((?x707 (concat ((_ extract 7 5) fields_expected8) (bvnot ((_ extract 4 4) fields_expected8)) ((_ extract 3 1) fields_expected8) (bvnot ((_ extract 0 0) fields_expected8)))))
(let (($x700 (= fields_byte8 ?x707)))
(let (($x505 (not $x700)))
(let (($x310 (= (bvxor fields_byte8 fields_expected8) (_ bv17 8))))
(let (($x551 (and (or $x310 $x700 (= (_ bv1 32) (_ bv1 32))) (or (not $x310) $x505 (= (_ bv0 32) (_ bv0 32))) (or (not $x310) $x700 (= (_ bv0 32) (_ bv1 32))) (or $x310 $x505 (= (_ bv1 32) (_ bv0 32))))))
(not $x551)))))))
(check-sat)
