; benchmark generated from python API
(set-info :status unknown)
(declare-fun publication_address64 () (_ BitVec 64))
(assert
 (let ((?x1979 (bvadd (bvor (bvand ((_ extract 31 0) publication_address64) (_ bv4294967288 32)) (_ bv2250374311 32)) (bvadd (bvor (bvand ((_ extract 31 0) publication_address64) (_ bv4294967288 32)) (_ bv2044592985 32)) (_ bv379073082 32)))))
(let ((?x1910 (bvand ((_ sign_extend 32) (bvand ?x1979 (_ bv255 32))) (_ bv18446744073709551608 64))))
(and true (or (bvugt ?x1910 (_ bv248 64)) (and (distinct (bvand ?x1910 (_ bv7 64)) (_ bv0 64)) true))))))
(check-sat)
