; benchmark generated from python API
(set-info :status unknown)
(declare-fun writers_output64 () (_ BitVec 64))
(declare-fun writers_descriptor_length64 () (_ BitVec 64))
(declare-fun writers_mapped_address64 () (_ BitVec 64))
(declare-fun writers_provider64 () (_ BitVec 64))
(assert
 (let (($x41 (and (distinct (bvadd (_ bv16 64) writers_output64) (bvadd writers_output64 (_ bv16 64))) true)))
(let (($x39 (and (distinct (bvadd (_ bv12 64) writers_output64) (bvadd writers_output64 (_ bv12 64))) true)))
(let (($x35 (and (distinct (bvadd (_ bv20 64) writers_output64) (bvadd writers_output64 (_ bv20 64))) true)))
(or (and (distinct writers_provider64 writers_provider64) true) (and (distinct writers_mapped_address64 writers_mapped_address64) true) (and (distinct writers_descriptor_length64 writers_descriptor_length64) true) $x35 (and (distinct ((_ zero_extend 32) (_ bv3072 32)) (_ bv3072 64)) true) $x39 $x41)))))
(check-sat)
