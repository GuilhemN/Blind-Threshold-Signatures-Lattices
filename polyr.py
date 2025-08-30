"""
polyr.py
Copyright (c) 2023 Plover Signature Team. See LICENSE.

=== Number Theoretic Transforms: Polynomial Ring Arithmetic.
"""

from polyr_params import *

### Internal functions: Polynomial arithmetic

def ntt(f, n=PLOVERSIGN_N, w=PLOVERSIGN_W, q=PLOVERSIGN_Q):
    """Forward NTT (negacyclic - x^n+1.) Note: Transforms f in place."""
    l = n // 2
    wi = 0
    while l > 0:
        for i in range(0, n, 2 * l):
            wi += 1
            z = w[wi]
            for j in range(i, i + l):
                x = f[j]
                y = (f[j + l] * z) % q
                f[j] = (x + y) % q
                f[j + l] = (x - y) % q
        l >>= 1
    return f

def intt(f, n=PLOVERSIGN_N, w=PLOVERSIGN_W, ni=PLOVERSIGN_NI, q=PLOVERSIGN_Q):
    """Inverse NTT (negacyclic - x^n+1.) Note: Transforms f in place."""
    l = 1
    wi = n
    while l < n:
        for i in range(0, n, 2 * l):
            wi -= 1
            z = w[wi]
            for j in range(i, i + l):
                x = f[j]
                y = f[j + l]
                f[j] = (x + y) % q
                f[j + l] = (z * (y - x)) % q
        l <<= 1
    #   normalize: ni = n^-1  (mod q)
    for i in range(n):
        f[i] = (ni * f[i]) % q
    return f

def mat_ntt(m):
    """NTT on a matrix-like object of polynomials (in place)."""
    for m_i in m:
        for m_ij in m_i:
            ntt(m_ij)
    return m

def mat_intt(m):
    """NTT^-1 on a matrix-like object of polynomials (in place)."""
    for m_i in m:
        for m_ij in m_i:
            intt(m_ij)
    return m

def mul_ntt(f, g, q=PLOVERSIGN_Q):
    """Multiplication of two polynomials (NTT domain.)"""
    return [(fi * gi) % q for fi,gi in zip(f,g)]

def poly_add(f, g, q=PLOVERSIGN_Q):
    """Add polynomials: return f + g (mod q)."""
    return [ (fi + gi) % q for fi,gi in zip(f,g) ]

def poly_sub(f, g, q=PLOVERSIGN_Q):
    """Substract polynomials: return f - g (mod q)."""
    return [ (fi - gi) % q for fi,gi in zip(f,g) ]

def poly_neg(f, q=PLOVERSIGN_Q):
    """Opposite of a polynomial: return -f (mod q)."""
    return [ (-fi) % q for fi in f ]

def poly_lshift(f, u, q=PLOVERSIGN_Q):
    """Left shift: Multiply coefficients by 2^u."""
    return [ (x << u) % q  for x in f ]

def poly_rshift(f, u, q=PLOVERSIGN_Q):
    """Right shift: Rounding divide by 2^u (in place)."""
    mid = 1 << (u - 1)
    return [ ((x + mid) >> u) % q for x in f ]

def poly_center(f, q=PLOVERSIGN_Q):
    """Center the modular coefficients of a polynomial around 0."""
    mid = q >> 1
    return [ ((fi + mid) % q) - mid for fi in f ]

def poly_cmul(f, c, q=PLOVERSIGN_Q):
    """Multiply polynomial f by constant c (mod q)."""
    return [ (fi * c) % q for fi in f ]

def mul_mat_vec_ntt(m, v):
    """Multiply NTT domain k*ell matrix "m" with column vector v."""
    k   = len(m)
    ell = len(m[0])
    r   = [[0] * PLOVERSIGN_N for _ in range(k)]
    for i in range(k):
        for j in range(ell):
            r[i] = poly_add(r[i], mul_ntt(m[i][j], v[j]) )
    return r

def is_invertible_poly(f, n=PLOVERSIGN_N, q=PLOVERSIGN_Q, w=PLOVERSIGN_W):
    """
    Check if a polynomial f is invertible in Z_q[x]/(x^n+1).
    Uses the NTT: f is invertible iff all its NTT coefficients are nonzero mod q.
    """
    f_ntt = f[:]
    ntt(f_ntt, n=n, w=w, q=q)
    return all(x % q != 0 for x in f_ntt)

