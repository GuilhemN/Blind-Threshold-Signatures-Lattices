#!/usr/bin/env python3
"""
blindsign_sec.py

Security estimation for Lattice-based Threshold Blind Signatures.

How to run: cd scripts && python blindsign_sec.py

Reference:
- Authors: Sebastian Faller, Guilhem Niot, and Michael Reichle
- Title: "Lattice-based Threshold Blind Signatures"
"""

import contextlib
import os
from dataclasses import dataclass, field
from math import sqrt, log, e, ceil, pi

import estimator.estimator as estimator

from sage.all import is_prime

# ---------------------------------------------------------------------------
Gaussian = estimator.ND.DiscreteGaussian
Uniform  = estimator.ND.UniformMod

LWEInstance = estimator.lwe_parameters.LWEParameters
LWEEstimate = estimator.LWE.estimate.rough

SISInstance = estimator.sis_parameters.SISParameters
SISEstimate = estimator.SIS.estimate.rough

# ---------------------------------------------------------------------------

def _bitsec(hardness: dict) -> int:
    """Return the bit-security level from a rough estimator result dict."""
    return int(log(min(hardness[x]["rop"] for x in hardness), 2))


@dataclass
class ThBlindSign:
    """
    Dataclass for Threshold Blind Signatures parameter sets.

    Hardness evaluations
    --------------------
    - key_recovery : Hint-MLWE reduction
    - blindness    : plain MLWE
    - forgery      : MSIS
    - mlwe_enc     : MLWE for the encryption layer
    """
    name: str
    kappa: int          # Target bit-security level
    Qs: int             # Number of signing queries
    maxT: int           # Maximum threshold
    q: int              # Modulus
    ptilde: int         # Rounding modulus
    n: int              # Ring degree
    beta: int           # Challenge norm bound (challenge coefficients in [-q/beta, q/beta])
    sigmask: int        # Gaussian std for secret key
    sigmarnd: int       # Gaussian std for randomness
    sigmaUx: int        # Gaussian std for key-blinding
    sigmaSx: float = field(init=False)   # Effective std after trapdoor sampling
    sigmaUnif: float | None = None       # Smoothing std (computed if None)
    B22: float = field(init=False)       # Forgery bound
    fast: bool = True   # Use rough estimates

    # Results
    key_recovery_bitsec: int = field(init=False)
    blindness_bitsec: int = field(init=False)
    forgery_bitsec: int = field(init=False)
    comm_per_party: int = field(init=False)

    def __post_init__(self):
        self.__hardness__()
        self.__sizes__()

    def __hardness__(self):
        # 1. Key recovery — corresponds to Hint-MLWE
        inv_var_sk  = self.sigmask  ** -2

        M = 2*ceil((self.q - 1) / 2 / self.beta) + 1
        inv_var_rnd = self.Qs * self.n * M**2/12 * self.sigmarnd ** -2
        sigma_0 = (inv_var_sk + inv_var_rnd) ** (-1/2)
        print(f"\n[{self.name}] __key_recovery__")
        print(f"  sigma_sk  = 2^{log(self.sigmask,  2):.2f}")
        print(f"  sigma_rnd = 2^{log(self.sigmarnd, 2):.2f}")
        print(f"  sigma_0   = 2^{log(sigma_0, 2):.2f}")

        Xs = Gaussian(sigma_0)
        Xe = Gaussian(sigma_0)
        instance_kr = LWEInstance(
            n=self.n,
            q=self.q,
            Xs=Xs,
            Xe=Xe,
            m=self.n,
            tag="key_recovery",
        )
        with contextlib.redirect_stdout(open(os.devnull, "w")):
            hardness_kr = LWEEstimate(instance_kr)
        self.key_recovery_bitsec = _bitsec(hardness_kr)
        print(f"  key_recovery_bitsec = {self.key_recovery_bitsec}")

        # 2. Blindness — plain MLWE with sigma_Ux
        print(f"\n[{self.name}] __blindness__")
        Xs_b = Gaussian(self.sigmaUx)
        Xe_b = Gaussian(self.sigmaUx)
        instance_bl = LWEInstance(
            n=self.n,
            q=self.q,
            Xs=Xs_b,
            Xe=Xe_b,
            m=self.n,
            tag="blindness",
        )
        with contextlib.redirect_stdout(open(os.devnull, "w")):
            hardness_bl = LWEEstimate(instance_bl)
        self.blindness_bitsec = _bitsec(hardness_bl)
        print(f"  sigmaUx           = 2^{log(self.sigmaUx, 2):.2f}")
        print(f"  blindness_bitsec  = {self.blindness_bitsec}")

        # 3. Compute sigma unif such that d is pseudo uniform even with a trapdoor injected
        print(f"\n[{self.name}] __trapdoor_params__")
        m = 3
        delta = 2**-self.kappa
        eps_exp = (2 * (m + 1) * self.n + self.kappa) / (log(self.q, 2) * m * self.n) / 2
        print(f"  eps = 2^{log(eps_exp, 2):.4f}")

        if self.sigmaUnif is None:
            self.sigmaUnif = (sqrt(self.n) * (1 / sqrt(2 * pi)) * log(2 * m * self.n * (1 + 1 / delta)) / pi * self.q ** (1 / m + eps_exp))
        print(f"  sigmaUnif = 2^{log(self.sigmaUnif, 2):.2f}")

        # 4. Compute resulting sigmaUx after use of trapdoor sampling gadget
        q1 = self.q / self.ptilde
        sigmaT = (self.sigmaUnif * sqrt(m) * sqrt(2 * self.n) * sqrt(self.kappa * log(2) + log(2 * self.n * m)))
        print(f"  sigmaT    = 2^{log(sigmaT, 2):.2f}")

        # smoothing parameter
        eps_smooth = 2**-128
        eta = sqrt(log(2 * self.n * (1 + 1/eps_smooth)) / pi)
        eta /= sqrt(2 * pi)

        self.sigmaSx = max(self.sigmarnd, eta * q1 * sigmaT)
        print(f"  sigmaSx   = 2^{log(self.sigmaSx, 2):.2f}")

        # 4. Forgery bound B22 and MSIS hardness
        print(f"\n[{self.name}] __forgery__")
        randomness = (
            sqrt(self.n) * e**(1/4)
            * (
                self.n * sqrt(2) * ceil((self.q - 1) / (2 * self.beta)) * self.sigmask
                + sqrt(2) * self.sigmaUx
                + sqrt(2 * self.maxT * self.sigmarnd**2 + 4 * self.sigmaSx**2)
            )
        )
        lowerbits_norm = sqrt(self.n) * (self.beta + self.ptilde) / sqrt(12)
        self.B22 = lowerbits_norm + randomness
        print(f"  randomness     = 2^{log(randomness, 2):.2f}")
        print(f"  lowerbits_norm = 2^{log(lowerbits_norm, 2):.2f}")
        print(f"  B22            = 2^{log(self.B22, 2):.2f}")

        instance_sis = SISInstance(
            n=self.n,
            q=self.q,
            length_bound=self.B22,
            m=self.n * 4,   # dim_preimage = 4
            norm=2,
            tag="forgery",
        )
        with contextlib.redirect_stdout(open(os.devnull, "w")):
            hardness_sis = SISEstimate(instance_sis)
        self.forgery_bitsec = _bitsec(hardness_sis)
        print(f"  forgery_bitsec = {self.forgery_bitsec}")

    def __sizes__(self):
        logq = ceil(log(self.q, 2))
        self.comm_per_party = int((2 * self.kappa + 2 * self.n * logq) // 8)

    def summary(self):
        sep = "-" * 50
        print(f"\n{sep}")
        print(f"Parameter set : {self.name}")
        print(f"  n={self.n}, q={self.q}~2^{log(self.q,2):.1f}, kappa={self.kappa}")
        print(f"  key_recovery : {self.key_recovery_bitsec} bits")
        print(f"  blindness    : {self.blindness_bitsec} bits")
        print(f"  forgery      : {self.forgery_bitsec} bits")
        print(f"  comm_per_party: {self.comm_per_party} bytes")
        print(sep)



def find_q(logq: int, n: int) -> int:
    """
    Find a prime q such that
	- q = 1 (mod 2*n)
    - ceil(log(q)) = logq
    """
    base = round(pow(2,logq))
    k = 1
    for q in range(base, base // 2, -1):
        if q > 2 and is_prime(q) and (q - 1) % (2 * n) == 0:
            return q
    raise ValueError(f"Could not find a prime q with ceil(log(q)) = {logq} and q = 1 (mod 2*n)")


# ---------------------------------------------------------------------------
if __name__ == "__main__":

    # Proved params
    proved = ThBlindSign(
        name="ThBlindSign_proved",
        kappa=128,
        Qs=2**50,
        maxT=16,
        q=2**60,
        n=2048,
        sigmask=2**15,
        sigmaUx=2**8,
        sigmarnd=2**47,
        beta=2**49,
        ptilde=2**50,
        fast=True,
    )
    proved.summary()

    # Heuristic params
    n = 2048
    ptilde = find_q(31.5, n)
    q1 = find_q(16.1, n)
    q = q1 * ptilde
    print(f"\nHeuristic params: ptilde = {ptilde} (2^{log(ptilde, 2):.1f}), q1 = {q1} (2^{log(q1, 2):.1f}), q = {q} (2^{log(q, 2):.1f})")
    heuristic = ThBlindSign(
        name="ThBlindSign_heuristic",
        kappa=128,
        Qs=2**50,
        maxT=16,
        q=q,
        n=2048,
        sigmask=2**15,
        sigmaUx=2,
        sigmarnd=int(2**37.5),
        beta=int(2**40),
        sigmaUnif=4,
        ptilde=ptilde,
        fast=True,
    )
    heuristic.summary()
