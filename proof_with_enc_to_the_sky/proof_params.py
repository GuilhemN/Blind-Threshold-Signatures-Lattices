# Create a header file with LNP proof system parameters for
# proving knowledge of a witness w in Rp^n (Rp = Zp[X]/(X^d + 1))
# such that
#
#   1. w satisfies a linear relation over Rp: Aw + t = 0
#   2. each element in a partition of w either ..
#      2.1 has binary coefficients only
#      2.2 satisfies an l2-norm bound
from math import sqrt, e
vname = "param"           # variable name


deg   = 2048               # ring Rp degree d
mod   = 199034774335489        # ring Rp modulus p
m,n   = 1+8,8+9
dim   = (m,n)             # dimensions of A in Rp^(m,n)

stdenc = 100
Benc = e**(1/4) * sqrt(9 * deg) * stdenc

cutoff = 21
Bcutoff = 2**(cutoff-1) * sqrt(deg*1*8)  # bound on the low bits of the witness
B = 2**46.23
Bproof = B / 2**cutoff  # bound on the high bits of the witness

wpart = [ list(range(4)), list(range(4, 8)), list(range(8, 8+9)) ]  # partition of w : [w]
wl2   = [ Bcutoff, Bproof, Benc ]  # l2-norm bounds    : l2(r1,r2) <= 109
wbin  = [ 0, 0, 0               ]  # binary coeffs  : n/a
wrej  = [ 0, 0, 0               ]  # rej. sampling  : on m w

# Optional: some linf-norm bound on w.
# Tighter bounds result in smaller proofs.
# If not specified, the default is the naive bound max(1,floor(max(wl2))).
wlinf = max(2**(cutoff-1), Bproof) # optional linf: some linf-norm bound on w.
