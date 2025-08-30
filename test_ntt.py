"""
test_ntt.py
Copyright (c) 2023 Plover Signature Team. See LICENSE.

=== Code for re-creating the NTT magic constants. Unit tests for NTT.
"""

from random import randrange
from polyr import *

if (__name__ == "__main__"):

    def _bitrev(x, l):
        """(TESTING) Return x with bits 0,1,..(l-1) in reverse order."""
        y = 0
        for i in range(l):
            y |= ((x >> i) & 1) << (l - i - 1)
        return y

    #   g=15 is the smallest generator of both prime fields of composite q.
    #   Reduce to subgroup of order 2*n to obtain "h" in gp-pari;
    #   g   = Mod(15, q)
    #   h   = g^(znorder(g)/(2*n))

    def _rand_poly(n=PLOVERSIGN_N, q=PLOVERSIGN_Q):
        """(TESTING) Random polynomial."""
        return [ randrange(q) for _ in range(n) ]

    def _conv_slow(f, g, n=PLOVERSIGN_N,q=PLOVERSIGN_Q):
        """(TESTING) Slow negacyclic convolution h = f*g (mod x^n+1)."""
        h = [0] * n
        for i in range(n):
            for j in range(n):
                x = (f[i] * g[j]) % q
                k = i + j
                if k >= n:
                    k -= n
                    x = -x                  # x^n == -1 (mod x^n + 1)
                h[k] = (h[k] + x) % q

        return h

    def _conv_fast(f, g, n=PLOVERSIGN_N, q=PLOVERSIGN_Q):
        """(TESTING) Fast NTT negacyclic convolution h = f*g (mod x^n+1)."""
        ft = _slow_ntt(f.copy())
        gt = _slow_ntt(g.copy())
        ht = [ ( ft[i] * gt[i] ) % q for i in range(n) ]
        return intt(ht)

    """
    q=PLOVERSIGN_Q
    h=Mod(84875905401930,q)
    rev(x)=sum(i=0,8,2^(8-i)*(floor(2^-i * x) % 2))
    """

    def _slow_ntt(f, n=PLOVERSIGN_N, q=PLOVERSIGN_Q, h=PLOVERSIGN_H):
        """(TESTING) Compute NTT via very slow polynomial evaluation."""
        ft = []
        fails = 0
        for i in range(n):
            #   yes, not a modexp!
            x = h**(2*_bitrev(i,PLOVERSIGN_LOGN)+1) % q
            #   horner's: y = f(x)
            y = 0
            for j in reversed(range(n)):
                y = (y * x + f[j]) % q
            ft += [y]
        return ft

    #   ---------------

    #   test convolutions
    for _ in range(5):
        f = _rand_poly()
        g = _rand_poly()
        print("_conv_fast():", _conv_slow(f, g) == _conv_fast(f, g))
        ft1 = ntt(f.copy())
        ft2 = _slow_ntt(f.copy())
        print("_slow_ntt():", ft1 == ft2)

