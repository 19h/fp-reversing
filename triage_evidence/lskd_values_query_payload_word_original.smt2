; benchmark generated from python API
(set-info :status unknown)
(assert
 (let ((?x549 (concat ((_ extract 7 0) ((_ extract 31 0) ((_ zero_extend 32) (_ bv4294967059 32)))) ((_ extract 7 0) ((_ extract 31 0) ((_ zero_extend 32) (_ bv39960 32)))))))
(let ((?x334 (concat (concat ?x549 ((_ extract 7 0) ((_ extract 31 0) ((_ zero_extend 32) (_ bv10270720 32))))) ((_ extract 7 0) ((_ extract 31 0) ((_ zero_extend 32) (_ bv2629340672 32)))))))
(and (distinct ?x334 (_ bv320339968 32)) true))))
(check-sat)
