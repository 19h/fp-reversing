; benchmark generated from python API
(set-info :status unknown)
(declare-fun output_root64 () (_ BitVec 64))
(declare-fun output_G64 () (_ BitVec 64))
(declare-fun output_E64 () (_ BitVec 64))
(declare-fun output_D64 () (_ BitVec 64))
(declare-fun output_B64 () (_ BitVec 64))
(declare-fun output_A64 () (_ BitVec 64))
(assert
 (let (($x620 (and (distinct output_root64 output_root64) true)))
(let (($x666 (or (and (distinct (bvadd (_ bv812 64) output_root64) (bvadd output_root64 (_ bv812 64))) true) (and (distinct output_A64 output_A64) true) (and (distinct output_B64 output_B64) true) (and (distinct output_D64 output_D64) true) (and (distinct output_E64 output_E64) true) (and (distinct output_G64 output_G64) true) (and (distinct (bvadd (_ bv284 64) output_root64) (bvadd output_root64 (_ bv284 64))) true) (and (distinct (bvadd (_ bv527 64) output_root64) (bvadd output_root64 (_ bv527 64))) true) $x620 (and (distinct (bvadd (_ bv228 64) output_root64) (bvadd output_root64 (_ bv228 64))) true))))
(and true $x666))))
(check-sat)
