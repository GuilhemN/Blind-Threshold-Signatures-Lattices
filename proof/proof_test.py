import sys
sys.path.append('../lazer/python')   # path to lazer module
from lazer import *     # lazer module
import hashlib          # for SHAKE128
import secrets          # for internal coins

# public randomness
shake128 = hashlib.shake_128(bytes.fromhex("00"))
PROOFPP = shake128.digest(32)
shake128 = hashlib.shake_128(bytes.fromhex("01"))
P1PP = shake128.digest(32)

from proof_params import mod, deg, m, n    # import swoosh parameters

from _proof_params_cffi import lib         # import proof system parameters
prover = lin_prover_state_t(P1PP, lib.get_params("param"))
verifier = lin_verifier_state_t(P1PP, lib.get_params("param"))

# define proof ring (R), expand public parameters (A) and enumerate proof key pair (pk,sk)
R = polyring_t(deg, mod)
A1 = polymat_t.urandom_static(R, m, n-m, mod, PROOFPP, 1)
A2 = polymat_t.identity(R, m)
A = polymat_t(R, m, n, [A1, A2])
sk = polyvec_t.urandom_bnd_static(R, n, -1, 1, secrets.token_bytes(32), 0)
pk = A*sk

# prover

prover.set_statement(A, -pk)
prover.set_witness(sk)

print("generate proof ...")
proof = prover.prove()
print_stopwatch_lnp_prover_prove(0)

# verifier

verifier.set_statement(A, -pk)

print("verify proof ... ")
try:
    verifier.verify(proof)
except:
    print("reject")
else:
    print("accept")
print_stopwatch_lnp_verifier_verify(0)
