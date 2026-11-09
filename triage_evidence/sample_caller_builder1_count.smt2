; benchmark generated from python API
(set-info :status unknown)
(declare-fun count_word_decoded32 () (_ BitVec 32))
(assert
 (let ((?x184 (bvadd (bvxor count_word_decoded32 (_ bv4286463995 32)) (bvand (bvshl count_word_decoded32 (_ bv1 32)) (_ bv4277960694 32)))))
(let ((?x187 (bvadd (bvadd ?x184 (_ bv2011686912 32)) (_ bv2291783685 32))))
(and (distinct ?x187 count_word_decoded32) true))))
(check-sat)
