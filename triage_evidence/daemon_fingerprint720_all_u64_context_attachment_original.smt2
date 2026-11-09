; benchmark generated from python API
(set-info :status unknown)
(declare-fun fingerprint_user64 () (_ BitVec 64))
(declare-fun fingerprint_destination64 () (_ BitVec 64))
(assert
 (let (($x21 (and (distinct (bvadd (_ bv96 64) fingerprint_user64) (bvadd fingerprint_user64 (_ bv96 64))) true)))
(let (($x18 (and (distinct fingerprint_destination64 fingerprint_destination64) true)))
(and true (or $x18 $x18 $x21)))))
(check-sat)
