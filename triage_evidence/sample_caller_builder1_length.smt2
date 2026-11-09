; benchmark generated from python API
(set-info :status unknown)
(declare-fun count_word_decoded32 () (_ BitVec 32))
(assert
 (let ((?x188 ((_ zero_extend 32) count_word_decoded32)))
(let ((?x198 (bvadd (bvadd (bvadd (bvxor ?x188 (_ bv4034099091305094143 64)) (bvand (bvshl ?x188 (_ bv1 64)) (_ bv8521693182 64))) (_ bv15802434061341393581 64)) (_ bv17056954994772615508 64))))
(and (distinct ?x198 ?x188) true))))
(check-sat)
