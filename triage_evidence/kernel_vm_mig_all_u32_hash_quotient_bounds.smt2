; benchmark generated from python API
(set-info :status unknown)
(declare-fun kmig_hash_input_integer () Int)
(assert
 (let (($x290 (>= kmig_hash_input_integer (+ 1031 (* 1031 (div (* 2132903255 kmig_hash_input_integer) 2199023255552))))))
(let ((?x228 (div (* 2132903255 kmig_hash_input_integer) 2199023255552)))
(let ((?x155 (* 1031 ?x228)))
(let (($x82 (>= kmig_hash_input_integer 0)))
(and $x82 (not (<= 4294967296 kmig_hash_input_integer)) (or (not (<= ?x155 kmig_hash_input_integer)) $x290)))))))
(check-sat)
