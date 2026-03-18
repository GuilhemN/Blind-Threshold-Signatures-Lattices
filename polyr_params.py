import numpy as np
from sympy import isprime, mod_inverse
from sympy.ntheory import factorint
from math import log, lcm

PLOVERSIGN_LOGN = 11
PLOVERSIGN_N = 2**PLOVERSIGN_LOGN

PLOVERSIGN_Q1 = 65537
PLOVERSIGN_Q2 = 3036983297
print("PLOVERSIGN_Q1 =", PLOVERSIGN_Q1)
print("PLOVERSIGN_Q2 =", PLOVERSIGN_Q2)

PLOVERSIGN_Q = PLOVERSIGN_Q1 * PLOVERSIGN_Q2
print("PLOVERSIGN_Q =", PLOVERSIGN_Q, " = 2^", log(PLOVERSIGN_Q, 2))
PLOVERSIGN_NI = mod_inverse(PLOVERSIGN_N, PLOVERSIGN_Q)   #   n^-1  (mod q)

"""
Find h the generator of a group of order 2*n in Z_q.
"""
def multiplicative_order(a, n):
    """
    Efficiently compute the multiplicative order of a modulo n.
    Assumes a and n are coprime.
    """
    if np.gcd(a, n) != 1:
        return 0
    phi = n - 1  # n is prime in our use-case, so phi(n) = n-1
    factors = factorint(phi)
    order = phi
    for p, e in factors.items():
        for _ in range(e):
            candidate = order // p
            if pow(a, candidate, n) == 1:
                order = candidate
            else:
                break
    return order

def find_h(q1, q2, n):
    q = q1 * q2
    
    # We need to find h such that:
    # 1. h has order 2*n in Z_q
    # 2. h^n ≡ -1 (mod q)
    # 3. h^(2*n) ≡ 1 (mod q)
    
    # Since q1 ≡ 1 (mod 2*n), there exists h1 of order 2*n in Z_q1
    # Since q2 ≡ 1 (mod 2*n), there exists h2 of order 2*n in Z_q2
    # We can use CRT to combine them
    
    # Find primitive 2*n-th root of unity modulo q1
    h1 = None
    for g1 in range(2, q1):
        order = multiplicative_order(g1, q1)
        if order % (2*n) == 0:
            # g1 has order divisible by 2*n, so g1^(order/(2*n)) has order 2*n
            candidate = pow(g1, order // (2*n), q1)
            if pow(candidate, n, q1) == q1 - 1:  # Check if candidate^n ≡ -1 (mod q1)
                h1 = candidate
                break
    if h1 is None:
        raise ValueError(f"No primitive 2*n-th root found modulo q1={q1}")
    
    # Find primitive 2*n-th root of unity modulo q2  
    h2 = None
    for g2 in range(2, q2):
        order = multiplicative_order(g2, q2)
        if order % (2*n) == 0:
            # g2 has order divisible by 2*n, so g2^(order/(2*n)) has order 2*n
            candidate = pow(g2, order // (2*n), q2)
            if pow(candidate, n, q2) == q2 - 1:  # Check if candidate^n ≡ -1 (mod q2)
                h2 = candidate
                break
    if h2 is None:
        raise ValueError(f"No primitive 2*n-th root found modulo q2={q2}")
    
    # Use Chinese Remainder Theorem to find h such that:
    # h ≡ h1 (mod q1)
    # h ≡ h2 (mod q2)
    from sympy import mod_inverse
    
    # CRT formula: h = h1*q2*inv(q2,q1) + h2*q1*inv(q1,q2)
    inv_q2_mod_q1 = mod_inverse(q2, q1)
    inv_q1_mod_q2 = mod_inverse(q1, q2)
    
    h = (h1 * q2 * inv_q2_mod_q1 + h2 * q1 * inv_q1_mod_q2) % q
    
    # Verify properties
    assert pow(h, n, q) == q - 1, f"h^n = {pow(h, n, q)} ≠ -1 = {q-1}"
    assert pow(h, 2*n, q) == 1, f"h^(2*n) = {pow(h, 2*n, q)} ≠ 1"
    
    return h

PLOVERSIGN_H = find_h(PLOVERSIGN_Q1, PLOVERSIGN_Q2, PLOVERSIGN_N)
print("PLOVERSIGN_H =", PLOVERSIGN_H)


def compute_w(q, h, lgn):

	def _modexp(x, e, n):
		"""(TESTING) Modular exponentiation: Compute x**e (mod n)."""
		y = 1
		while e > 0:
			if e & 1 == 1:
				y = (y * x) % n
			x = (x * x) % n
			e >>= 1
		return y

	def _bitrev(x, l):
		"""(TESTING) Return x with bits 0,1,..(l-1) in reverse order."""
		y = 0
		for i in range(l):
			y |= ((x >> i) & 1) << (l - i - 1)
		return y

	"""(TESTING) Re-generate the NTT "tweak" table."""
	n   = 2**lgn
	w   = []
	for i in range(n):
		j = _bitrev(i, lgn)
		x = (_modexp(h, j, q)) % q
		w.append(x)
	
	return w


PLOVERSIGN_W = compute_w(PLOVERSIGN_Q, PLOVERSIGN_H, PLOVERSIGN_LOGN)