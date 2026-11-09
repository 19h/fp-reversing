; benchmark generated from python API
(set-info :status unknown)
(declare-fun byte8 () (_ BitVec 8))
(assert
 (let ((?x40 (concat (concat (concat (concat byte8 byte8) byte8) byte8) byte8)))
(let ((?x31 (bvmul ((_ zero_extend 56) byte8) (_ bv72340172838076673 64))))
(and (distinct ?x31 (concat (concat (concat ?x40 byte8) byte8) byte8)) true))))
(check-sat)
