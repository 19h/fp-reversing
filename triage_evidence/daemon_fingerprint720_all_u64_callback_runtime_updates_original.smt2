; benchmark generated from python API
(set-info :status unknown)
(declare-fun fingerprint_SP64 () (_ BitVec 64))
(declare-fun fingerprint_X64 () (_ BitVec 64))
(declare-fun fingerprint_Y64 () (_ BitVec 64))
(assert
 (let ((?x325 (bvxor (bvsub fingerprint_Y64 fingerprint_X64) (bvadd fingerprint_SP64 (_ bv88 64)))))
(let ((?x408 (bvmul (_ bv18446744073709551615 64) fingerprint_X64)))
(let ((?x414 (bvadd fingerprint_Y64 ?x408)))
(let ((?x405 (bvadd (_ bv88 64) fingerprint_SP64)))
(let (($x446 (and (distinct (bvmul (_ bv173855951 64) (bvxor (_ bv8345247215164248486 64) ?x405 ?x414)) (bvmul (bvxor ?x325 (_ bv8345247215164248486 64)) (_ bv173855951 64))) true)))
(let (($x387 (and (distinct (bvadd (_ bv8345247215164248486 64) (bvmul (_ bv173855951 64) (bvxor ?x405 ?x414))) (bvadd (bvmul ?x325 (_ bv173855951 64)) (_ bv8345247215164248486 64))) true)))
(and true (or $x387 $x446)))))))))
(check-sat)
