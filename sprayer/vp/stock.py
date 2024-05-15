from c2.sprayer.ccode.var import Var, VT

# -------------------------------------------------------------------------------------

# STOCK_vls counted from 1, sub-vl(s) - from 0

# vls1
STOCK_vls1_vl0 = [Var(VT.i8, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
                  Var(VT.u16, [21, 22, 23]),
                  Var(VT.i32, [31, 32, 33, 34, 35, 36, 37, 38, 39, 40])]
STOCK_vls1_vl1 = [Var(VT.u32, [101, 102, 103]),
                  Var(VT.i8, [201, 202, 203, 204, 205, 206, 207, 208, 209, 210]),
                  Var(VT.i16, [311])]
STOCK_vls1_vls = [STOCK_vls1_vl0, STOCK_vls1_vl1]

# vls2 - bigger, but only one vl (for vrp_sample.py)
STOCK_vls2_vl0 = [Var(VT.i16, [1,2,3,4,5,6,7,8,9,10,11,12]),
                  Var(VT.u8, [20,21,22,23,24,25,26,27,28,29]),
                  Var(VT.i8, [40,41,42,43,44,45,46,47,48]),
                  Var(VT.u32, [30,31,32,33,34,35]),
                  Var(VT.u16, [51,52,53,54,55,56,57,58,59,60,61,62,63,65,65]),
                  Var(VT.u8, [70,71,72,73,74,75,76,77,78,79,80,81,82])
                  ]
STOCK_vls2_vls = [STOCK_vls2_vl0]

# -------------------------------------------------------------------------------------

# #DiagonalVls |_vls| should be `diagonal` (eq number of vls, vars and values). Let it be 3x3x3.
STOCK_diagonalvls_vl0 = [Var(VT.i8, [1, 2, 3]), Var(VT.u16, [4, 5, 7]), Var(VT.i32, [7, 8, 9])]
STOCK_diagonalvls_vl1 = [Var(VT.u32, [1, 2, 3]), Var(VT.i8, [4, 5, 7]), Var(VT.i16, [7, 8, 9])]
STOCK_diagonalvls_vl2 = [Var(VT.i16, [1, 2, 3]), Var(VT.u32, [4, 5, 7]), Var(VT.i8, [7, 8, 9])]
STOCK_diagonalvls_vls = [STOCK_diagonalvls_vl0, STOCK_diagonalvls_vl1, STOCK_diagonalvls_vl2]

# -------------------------------------------------------------------------------------
