; benchmark generated from python API
(set-info :status unknown)
(declare-fun kmig_OutBody64 () (_ BitVec 64))
(declare-fun kmig_OutHead64 () (_ BitVec 64))
(declare-fun kmig_trailer64 () (_ BitVec 64))
(declare-fun kmig_InBody64 () (_ BitVec 64))
(declare-fun kmig_InHead64 () (_ BitVec 64))
(assert
 (or (and (distinct (_ bv18446741874885046668 64) (_ bv18446741874885046668 64)) true) (and (distinct (_ bv14979 64) (_ bv14979 64)) true) (and (distinct kmig_InHead64 kmig_InHead64) true) (and (distinct kmig_InBody64 kmig_InBody64) true) (and (distinct kmig_trailer64 kmig_trailer64) true) (and (distinct kmig_OutHead64 kmig_OutHead64) true) (and (distinct kmig_OutBody64 kmig_OutBody64) true)))
(check-sat)
