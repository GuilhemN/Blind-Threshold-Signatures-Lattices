"""
ploversign_core.py
Copyright (c) 2023 Plover Signature Team. See LICENSE.

=== Masked Plover signature scheme: Core implementation.
"""

from Crypto.Hash import SHAKE256
from sample_gauss import sample_discrete_gaussian_poly
from polyr import *
from encoding import encode_bits
from math import ceil, sqrt, log, floor
import secrets
from functools import reduce


# Compute Lagrange coefficient for a set of participating servers
# S: list of indices of participating servers (1-based)
def lagrange_coeff(S, j, q):
    """
    S: list of indices (1-based)
    j: index in S for which to compute the coefficient
    q: modulus
    Returns: Lagrange coefficient for S[j] at x=0 mod q
    """
    num = 1
    den = 1
    for xm in S:
        if xm != j:
            num = (num * (-xm)) % q
            den = (den * (j - xm)) % q
    # Compute modular inverse of denominator
    inv_den = pow(den, -1, q)
    return (num * inv_den) % q

BYTEORDER = "little"

class PloverSign:

    # Public Interface

    # Initialize the PloverSign instance
    def __init__(self,  bitsec,
                        q, logdivide, sigma_sk, sigma_sx, sigma_ux, sigma_rnd, B, n,
                        kappa=512):
        """Initialize a Plover instance."""

        self.name   =   f'Plover-{bitsec}'
        self.bitsec =   bitsec
        self.q      =   q
        self.logdivide = logdivide
        self.q_bits =   self.q.bit_length()
        self.n      =   n
        self.sigma_sk = sigma_sk
        self.sigma_sx = sigma_sx
        self.sigma_ux = sigma_ux
        self.sigma_rnd = sigma_rnd
        self.B      =   B

        self.sec    =   self.bitsec//8  # pre-image resistance, bytes
        self.crh    =   2*self.sec      # collision resistance, bytes
        self.tr_sz  =   self.crh        # tr digest H(pk) size

    # Define public parameters
        seed = 0
        while not is_invertible_poly(self._expand_poly(bytes([seed]), 'a'), n=self.n, q=self.q):
            seed += 1
        self.seed = bytes([seed])

        # Calculate derived parameters
        self._compute_metrics()

    def keygen(self, T=None, N=None):
        """Plover keypair generation. If t and n_shares are given, perform Shamir sharing of the secret key."""

        # Expand polynomial 'a' using the seed
        a_ntt = ntt(self._expand_poly(self.seed, 'a'))

        # Sample polynomials e and s from discrete Gaussian
        seed = secrets.token_bytes(32)
        e = sample_discrete_gaussian_poly(self.sigma_sk, seed=seed, info=b'e')
        s = sample_discrete_gaussian_poly(self.sigma_sk, seed=seed, info=b's')
        s_ntt = ntt(s.copy())

        # Compute b = a * s + e
        b_ntt = mul_ntt(a_ntt, s_ntt)
        b = intt(b_ntt)
        b = poly_add(b, e)

        # Adjust b for rounding and modulus
        b[0] = (2**self.logdivide - b[0]) % self.q
        for i in range(1, self.n):
            b[i] = (-b[i]) % self.q

        vk = b

        # If no threshold parameters, return single secret key and verification key
        if T is None or N is None:
            sk = (b, s_ntt)
            return sk, vk

        # Shamir sharing of s_ntt: each coefficient is shared independently over Z_q
        def shamir_share_secret(secret, T, N, q):
            """
            secret: list of ints (coefficients)
            T: threshold
            N: number of shares
            q: modulus
            Returns: list of N lists, each a share (same length as secret)
            """
            import random
            shares = [ [0]*len(secret) for _ in range(N) ]
            for idx, s_coeff in enumerate(secret):
                # Generate random polynomial for Shamir sharing
                coeffs = [s_coeff] + [random.randrange(q) for _ in range(T-1)]
                # Evaluate polynomial at x=1..N
                for i in range(1, N+1):
                    val = 0
                    for j, c in enumerate(coeffs):
                        val = (val + c * pow(i, j, q)) % q
                    shares[i-1][idx] = val
            return shares

        # Each share is a vector of length self.n
        s_ntt_shares = shamir_share_secret(s_ntt, T, N, self.q)

        # Generate pairwise seeds for zero share algorithm
        zero_share_seeds = [[secrets.token_bytes(32) for _ in range(N)] for _ in range(N)]

        # Return all shares as secret keys: (b, s_ntt_share)
        sk_shares = [ (i+1, b, s_share, [(zero_share_seeds[i][j], zero_share_seeds[j][i]) for j in range(N)]) for i, s_share in enumerate(s_ntt_shares) ]
        return sk_shares, vk
    
    def compute_c1(self, u, w):
        """Compute the c1 polynomial for signature decomposition, including bit sampling."""
        # Use a random bit from w to decide sign for decomposition
        sign_bit = SHAKE256.new(b'sign' + encode_bits(w, self.q_bits)).read(1)[0] & 1
        if sign_bit:
            u_decomp = poly_neg(u)
        else:
            u_decomp = u
        c1 = [0] * self.n
        mid1 = self.maxc1
        mid2 = 1 << (self.logdivide - 1)
        mid = mid1 * (1 << self.logdivide) + mid2
        for k in range(self.n):
            c1[k] = ((((u_decomp[k] + mid) % self.q) >> self.logdivide) - mid1) % self.q
        if sign_bit:
            c1 = poly_neg(c1)
        return c1
    
    def sign_user_init(self, vk, tr, msg):
        """Initiate blind signing procedure: first message of the user."""

        u = self._msg_hash(tr, msg)
        seed = secrets.token_bytes(32)
        x_ = [sample_discrete_gaussian_poly(self.sigma_ux, seed=seed, info=bytes([ord('U'), ord('x'), k])) for k in range(2)]

        # Expand polynomial 'a' for signing
        a_ntt = ntt(self._expand_poly(self.seed, 'a'))

        t__ntt = mul_ntt(ntt(x_[1].copy()), a_ntt)
        t_ = intt(t__ntt)
        t_ = poly_add(t_, x_[0])
        t_ = poly_add(t_, u)

        st_u = (x_, t_, u, msg, vk)

        return st_u, t_
    
    def sign_server1(self, sk, pm_u, SS):
        """Blind signing procedure: first round of messages of the server."""
        i, b, s_ntt, seeds = sk
        a_ntt = ntt(self._expand_poly(self.seed, 'a'))

        # Sample r, p and compute w = a * r + p
        seed = secrets.token_bytes(32)
        r = sample_discrete_gaussian_poly(self.sigma_rnd, seed=seed, info=b'r')
        r_ntt = ntt(r.copy())
        p = sample_discrete_gaussian_poly(self.sigma_rnd, seed=seed, info=b'p')
        wi_ntt = mul_ntt(a_ntt, r_ntt)
        wi = intt(wi_ntt)
        wi = poly_add(wi, p)

        cmti = SHAKE256.new(bytes([i]) + encode_bits(wi, self.q_bits)).read(32)

        st_s = (SS, r, pm_u, wi)

        return st_s, cmti
    
    def sign_server2(self, sk, st_s, pm_s1):
        """Blind signing procedure: first round of messages of the server."""

        SS, r, pm_u, wi = st_s # unpack the state
        st_s = (*st_s, pm_s1) # store the first server messages in the state

        return st_s, wi

    def sign_server3(self, sk, tr, st_s, pm_s2):
        """Blind signing procedure: second round of messages of the server."""

        SS, r, pm_u, wi, pm_s1 = st_s
        (i, b, s_ntt, seeds) = sk
        b_ntt = ntt(b.copy())

        for j, cmti, wi in zip(SS, pm_s1, pm_s2):
            assert(cmti == SHAKE256.new(bytes([j]) + encode_bits(wi, self.q_bits)).read(32))

        # Aggregate commitments from all servers
        w = reduce(poly_add, pm_s2)

        # Sample x for signing
        seedx = SHAKE256.new(tr + encode_bits(w, self.q_bits)).read(32)
        x = [sample_discrete_gaussian_poly(self.sigma_sx, seed=seedx, info=bytes([ord('S'), ord('x'), k])) for k in range(4)]
        x = [[vi % self.q for vi in v] for v in x]  # ensure 

        # Start signing process
        t_ = pm_u

        # Compute t = [1 a b d] * x
        a_ntt = ntt(self._expand_poly(self.seed, 'a'))
        d_ntt = ntt(self._expand_poly(self.seed, 'd'))

        t_ntt = mul_ntt(ntt(x[1].copy()), a_ntt)
        t_ntt = poly_add(t_ntt, mul_ntt(ntt(x[2].copy()), b_ntt))
        t_ntt = poly_add(t_ntt, mul_ntt(ntt(x[3].copy()), d_ntt))
        t = intt(t_ntt)
        t = poly_add(t, x[0])

        # Add t' to t
        t = poly_add(t, t_)
        # TODO: sample PreSmp error

        # Compute c1 using bit sampling and decomposition
        c1 = self.compute_c1(poly_sub(t, w), w)
        c1_ntt = ntt(c1.copy())

        # Compute z2 as lambda * c1 * s + r
        lamb = lagrange_coeff(SS, i, self.q)
        z2_ntt = poly_cmul(mul_ntt(c1_ntt, s_ntt), lamb)
        z2 = intt(z2_ntt)
        z2 = poly_add(z2, r)

        # Add zero share to z2
        # TODO: add transcript to zero share context
        zshare = self.zero_share(b"", seeds, SS, i)
        z2 = poly_add(z2, zshare)

        return z2

    def sign_server_aggregate(self, pm_s2, pm_s3):
        """Aggregate the server's messages from the third round of signing."""

        # Aggregate commitments from all servers
        w = reduce(poly_add, pm_s2)

        z2 = [0] * self.n

        for pm in pm_s3:
            z2i = pm
            z2 = poly_add(z2, z2i)
        
        return (z2, w)

    def sign_user_final(self, tr, st_u, pm_s):
        """Complete blind signing procedure: second message of the user."""

        (x_, t_, u, msg, vk) = st_u
        b = vk
        b_ntt = ntt(b.copy())

        # Expand polynomial 'a' for user finalization
        a_ntt = ntt(self._expand_poly(self.seed, 'a'))
        d_ntt = ntt(self._expand_poly(self.seed, 'd'))

        (z2, w) = pm_s

        # Recover x for user finalization
        seedx = SHAKE256.new(tr + encode_bits(w, self.q_bits)).read(32)
        x = [sample_discrete_gaussian_poly(self.sigma_sx, seed=seedx, info=bytes([ord('S'), ord('x'), k])) for k in range(4)]
        x = [[vi % self.q for vi in v] for v in x]  # ensure 

        # Compute t for user finalization
        t_ntt = mul_ntt(ntt(x[1].copy()), a_ntt)
        t_ntt = poly_add(t_ntt, mul_ntt(ntt(x[2].copy()), b_ntt))
        t_ntt = poly_add(t_ntt, mul_ntt(ntt(x[3].copy()), d_ntt))
        t = intt(t_ntt)
        t = poly_add(t, x[0])

        # Add t' to t
        t = poly_add(t, t_)
        # TODO: sample PreSmp error

        # Recover c1 for user finalization
        c1 = self.compute_c1(poly_sub(t, w), w)

        z2 = poly_sub(poly_sub(z2, x_[1]), x[1])
        z3 = poly_sub(c1, x[2])
        z4 = poly_neg(x[3])

        sig = (z2, z3, z4)

        return sig

    def verify_msg(self, vk, tr, msg, sig):
        """Verification procedure of Plover (core: verifies msg)."""

        # Unpack signature and verification key
        (z2, z3, z4) = sig
        b = vk

        # Check bounds for signature validity

        # Expand polynomial 'a' for verification
        a_ntt = ntt(self._expand_poly(self.seed, 'a'))
        d_ntt = ntt(self._expand_poly(self.seed, 'd'))

        # Compute message hash for verification
        u = self._msg_hash(tr, msg)

        if self._check_bounds(u, a_ntt, b, d_ntt, z2, z3, z4) == False:
            return False

        return True

    # Internal methods

    def _compute_metrics(self):
        """Derive rejection bounds from parameters."""

        # Maximum absolute value of a coefficient of c_1
        self.maxc1 = (((self.q-1) >> self.logdivide) + 1) >> 1

    def _check_bounds(self, u, a_ntt, b, d_ntt, z2, z3, z4):
        """Check signature bounds. Return True iff bounds are acceptable."""

        b_ntt = ntt(b.copy())

        # Compute z1 = u - a*z_2 + t*c_1
        z2_ntt = ntt(z2.copy())
        z3_ntt = ntt(z3.copy())
        z4_ntt = ntt(z4.copy())

        z1_ntt = [a_ntt[i]*z2_ntt[i] + b_ntt[i]*z3_ntt[i] + d_ntt[i]*z4_ntt[i] for i in range(self.n)]
        z1 = intt(z1_ntt)
        z1 = poly_sub(u, z1)

        # Compute norm 2 for the full vector
        sq_n = 0
        for v in poly_center(z1):
            sq_n += v*v
        for v in poly_center(z2):
            sq_n += v*v
        for v in poly_center(z3):
            sq_n += v*v
        for v in poly_center(z4):
            sq_n += v*v

        def poly_norm(poly):
            """Compute the Euclidean norm of a polynomial (list of numbers)."""
            return sqrt(sum(x*x for x in poly))
        
        print(f"norms: z1 = {log(poly_norm(poly_center(z1)),2)}, z2 = {log(poly_norm(poly_center(z2)),2)}, z3 = {log(poly_norm(poly_center(z3)),2)}, z4 = {log(poly_norm(poly_center(z4)),2)}")
        
        return sq_n <= self.B**2
        

    def _decode(self, mp):
        """Decode(): Collapse shares into a single polynomial."""
        r = mp[0].copy()
        for p in mp[1:]:
            r = poly_add(r, p)
        return r

    def _xof_sample_q(self, seed):
        """Expand a seed to n uniform values [0,q-1] using a XOF."""
        blen = (self.q_bits + 7) // 8
        mask = (1 << self.q_bits) - 1

        xof = SHAKE256.new(seed)
        v = [0] * self.n
        i = 0
        while i < self.n:
            z = xof.read(blen)
            x = int.from_bytes(z, BYTEORDER) & mask
            if (x < self.q):
                v[i] = x
                i += 1
        return v

    def _expand_poly(self, seed, type):
        """ExpandA(): Expand "seed" into a polynomial."""

        # Expand seed using XOF for polynomial generation
        xof_in  = bytes([ord(type), 0, 0, 0, 0, 0, 0, 0]) + seed
        return self._xof_sample_q(xof_in)
    
    def zero_share(self, x, seeds, SS, i):
        """Sample a zero share for user i in the signing set SS."""

        s = [0] * self.n
        for j in SS:
            if j != i:
                seed1 = SHAKE256.new(seeds[j-1][0] + x).read(32)
                seed2 = SHAKE256.new(seeds[j-1][1] + x).read(32)

                s = poly_add(s, self._xof_sample_q(seed1))
                s = poly_sub(s, self._xof_sample_q(seed2))

        return s

    def _msg_hash(self, tr, msg):
        """Compute the message hash for the signature (a single hash)."""

        xof_in  = bytes([ord('h'), 0, 0, 0, 0, 0, 0, 0]) + tr + msg

        return self._xof_sample_q(xof_in)

    def prove_signature_existence(self, vk, tr, msg, sig):
        """
        Prove the existence of a signature using the public matrix [1 a b d] and the lazer library.
        Returns the proof object.
        """
        u = self._msg_hash(tr, msg) # message hash

        # Compute matrix A and signature vector sigvec such that A * sigvec = u

        # Expand a and d as polynomials of degree n
        a = self._expand_poly(self.seed, 'a')
        a_ntt = ntt(a.copy())
        d = self._expand_poly(self.seed, 'd')
        d_ntt = ntt(d.copy())
        b = vk
        b_ntt = ntt(b.copy())

        A = [{0: 1}, a, b, d]

        # Recover z1 for proof
        (z2, z3, z4) = sig

        z2_ntt = ntt(z2.copy())
        z3_ntt = ntt(z3.copy())
        z4_ntt = ntt(z4.copy())

        z1_ntt = [a_ntt[i]*z2_ntt[i] + b_ntt[i]*z3_ntt[i] + d_ntt[i]*z4_ntt[i] for i in range(self.n)]
        z1 = intt(z1_ntt)
        z1 = poly_sub(u, z1)

        sigvec = list(map(poly_center, [z1, z2, z3, z4]))

        # Produce a proof of signature existence
        import sys
        sys.path.append('lazer/python')
        from lazer import poly_t, polyring_t, polymat_t, polyvec_t, lin_prover_state_t
        import hashlib
        from proof._proof_params_cffi import lib
        from proof.proof_params import mod, deg, m, n, cutoff, Bcutoff, Bproof

        # Prepare public randomness for proof
        shake128 = hashlib.shake_128(bytes.fromhex("01"))
        P1PP = shake128.digest(32)

        # Prepare the ring and matrix for proof
        R = polyring_t(deg, mod)
        A1 = [poly_t(R, col) for col in A]  # Convert to poly_t
        A2 = [2**cutoff * col for col in A1]  # Scale by cutoff

        Afinal = polymat_t(R, 1, 8, [polymat_t(R, 1, 4, A1), polymat_t(R, 1, 4, A2)])  # Create the polymat_t

        # Create the signature vector for proof
        def decompose_p(p):
            """Decompose a polynomial into two parts based on cutoff."""
            hbits = poly_rshift(p, cutoff)
            lbits = poly_sub(p, poly_lshift(hbits, cutoff))
            return lbits, hbits
        
        # Decompose each polynomial in sigvec for proof
        z1, z2, z3, z4 = sigvec
        z1_l, z1_h = decompose_p(poly_center(z1))
        z2_l, z2_h = decompose_p(poly_center(z2))
        z3_l, z3_h = decompose_p(poly_center(z3))
        z4_l, z4_h = decompose_p(poly_center(z4))

        sigvec = polyvec_t(R, 8, [poly_t(R, v) for v in [z1_l, z2_l, z3_l, z4_l, z1_h, z2_h, z3_h, z4_h]])
        sigvec.redc()

        # Set up the prover for signature existence
        prover = lin_prover_state_t(P1PP, lib.get_params("param"))
        prover.set_statement(Afinal, polyvec_t(R, 1, [-poly_t(R, u)]))  # For existence, right-hand side is 0
        prover.set_witness(sigvec)

        # Generate the proof of signature existence
        proof = prover.prove()
        
        return proof

    def verify_signature_existence(self, vk, tr, msg, proof):
        """
        Verify the proof of existence of a signature using the lazer library.
        Returns True if the proof is valid, False otherwise.
        """
        u = self._msg_hash(tr, msg)

        # Reconstruct the matrix A as in the prover for verification
        a = self._expand_poly(self.seed, 'a')
        d = self._expand_poly(self.seed, 'd')
        b = vk

        import sys
        sys.path.append('lazer/python')
        from lazer import poly_t, polyring_t, polymat_t, polyvec_t, lin_verifier_state_t
        import hashlib
        from proof._proof_params_cffi import lib
        from proof.proof_params import mod, deg, m, n, cutoff

        shake128 = hashlib.shake_128(bytes.fromhex("01"))
        P1PP = shake128.digest(32)

        R = polyring_t(deg, mod)
        A = [{0: 1}, a, b, d]
        A1 = [poly_t(R, col) for col in A]
        A2 = [2**cutoff * col for col in A1]
        Afinal = polymat_t(R, 1, 8, [polymat_t(R, 1, 4, A1), polymat_t(R, 1, 4, A2)])

        rhs = polyvec_t(R, 1, [-poly_t(R, u)])

        verifier = lin_verifier_state_t(P1PP, lib.get_params("param"))
        verifier.set_statement(Afinal, rhs)

        try:
            verifier.verify(proof)
            return True  # Verification passed
        except:
            return False  # Verification failed

# Some testing code for demonstration and validation

if (__name__ == "__main__"):

    def chksum(v, q=549824583172097,g=15,s=31337):
        """Simple recursive poly/vector/matrix checksum routine."""
        if isinstance(v, int):
            return ((g * s + v) % q)
        elif isinstance(v, list):
            for x in v:
                s = chksum(x,q=q,g=g,s=s)
        return s

    def chkdim(v, s=''):
        t = v
        while isinstance(t, list):
            s += '[' + str(len(t)) + ']'
            t = t[0]
        s += ' = ' + str(chksum(v))
        return s

    # Create one instance here for testing
    iut = PloverSign(  bitsec=128, q=PLOVERSIGN_Q, logdivide=40,
        sigma_sk=1, sigma_sx=5, sigma_ux=5, sigma_rnd=5, B=2**44, 
        n=PLOVERSIGN_N)

    print(f'name = {iut.name}')

    
    print("=== Threshold Keygen ===")
    T = 16
    N = 16
    sks, vk = iut.keygen(T, N)

    for _ in range(5):
        tr = bytes(range(iut.tr_sz))
        msg = bytes(range(3))

        print("=== Threshold Blind Sign ===")
        st_u, pm_u = iut.sign_user_init(vk, tr, msg)

        st_s = [None] * T
        pm_s1 = [None] * T
        for i in range(T):
            st_s[i], pm_s1[i] = iut.sign_server1(sks[i], pm_u, list(range(1, T+1)))

        pm_s2 = [None] * T
        for i in range(T):
            st_s[i], pm_s2[i] = iut.sign_server2(sks[i], st_s[i], pm_s1)

        pm_s3 = [None] * T
        for i in range(T):
            pm_s3[i] = iut.sign_server3(sks[i], tr, st_s[i], pm_s2)

        pm_s = iut.sign_server_aggregate(pm_s2, pm_s3)
        sig = iut.sign_user_final(tr, st_u, pm_s)
        print(chkdim(sig[0], 'sig: z2'))
        print(chkdim(sig[1], 'sig: c1'))

        print("=== Verify ===")
        rsp = iut.verify_msg(vk, tr, msg, sig)
        print(rsp)
        assert(rsp is True)

        proof = iut.prove_signature_existence(vk, tr, msg, sig)
        assert(iut.verify_signature_existence(vk, tr, msg, proof) is True)
