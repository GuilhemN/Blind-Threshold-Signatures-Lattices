import math
from polyr_params import *
from Crypto.Hash import SHAKE256

def sample_discrete_gaussian_poly(sigma, seed, info, n=PLOVERSIGN_N):
    """
    Sample a polynomial/vector of length n from a discrete Gaussian with stddev sigma.
    If seed is provided, use SHAKE256(seed || info || counter) to generate randomness deterministically.
    """

    if seed is not None:
        # Deterministic sampling using SHAKE256
        xof = SHAKE256.new(seed + info)
        def getrandbits(k):
            # Return k random bits from XOF
            nbytes = (k + 7) // 8
            return int.from_bytes(xof.read(nbytes), 'little') & ((1 << k) - 1)
        rng = getrandbits
    else:
        import random
        rng = lambda k: random.getrandbits(k)

    def sample_discrete_gaussian(sigma):
        # Inverse CDF method using the Box-Muller transform for normal,
        # then rounding to nearest integer.
        # Note: This is not constant-time.
        u1 = (rng(53) + 1) / (1 << 53)
        u2 = (rng(53) + 1) / (1 << 53)
        z = math.sqrt(-2.0 * math.log(u1)) * math.cos(2 * math.pi * u2)
        return int(round(z * sigma))

    poly = [sample_discrete_gaussian(sigma) for _ in range(n)]
    return poly
