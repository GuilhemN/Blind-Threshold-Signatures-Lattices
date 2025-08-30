"""
plover_api.py
Copyright (c) 2023 Plover Signature Team. See LICENSE.

=== Masked Plover signature scheme: Serialization, parameters, BUFF interface.
"""

from Crypto.Hash import SHAKE256
from ploversign_core import PloverSign
from polyr import *
from encoding import encode_bits, decode_bits
from math import log, ceil
import time

#   Encoding and decoding methods for NIST Test Vectors

class NIST_PloverSign(PloverSign):

    def __init__(self, *args, **kwargs):
        """This is a subclass that provides serialization and BUFF."""
        super().__init__(*args, **kwargs)

        #   nist serialization sizes
        self.vk_sz  =   (self.n * self.q_bits // 8)
        self.sk_sz  =   (self.vk_sz +
                            (self.n * self.q_bits) // 8)

    def encode_vk(self, vk):
        """Serialize the signature verification (public) key."""
        t = vk
        b = encode_bits(t, self.q_bits)
        return b

    def encode_sk(self, sk):
        """Serialize the masked signing key."""
        (t, s) = sk

        #   encode public key
        b = self.encode_vk(t)

        #   encode secret
        b += encode_bits(s, self.q_bits)

        return b

    def decode_vk(self, b):
        """Decode the verification key from bytes."""
        l = 0
        vk, pl = decode_bits(b[l:], self.q_bits, self.n);
        l += pl

        #   compute the "tr" hash from serialized public key
        tr = SHAKE256.new(b[0:l]).read(self.tr_sz)

        return vk, tr, l

    def decode_sk(self, b):
        """Decode a signing key from bytes."""

        #   decode public key
        vk, tr, l = self.decode_vk(b)
        t = vk

        #   decode secret
        s,sl =   decode_bits(b[l:], self.q_bits, self.n)
        l       +=  sl

        sk = (t, s)
        return sk, tr, l

    def encode_sig(self, sig):
        """Serialize a signature as bytes. No zero padding / length check."""
        (z2, z3, z4) = sig

        s = encode_bits(z2, self.q_bits)
        s += encode_bits(z3, self.q_bits)
        s += encode_bits(z4, self.q_bits)

        return s

    def decode_sig(self, s):
        """Deserialize a signature."""
        i = 0
        z2, pi = decode_bits(s[i:], self.q_bits, self.n, False)
        i += pi
        z3, pi = decode_bits(s[i:], self.q_bits, self.n, False)
        i += pi
        z4, pi = decode_bits(s[i:], self.q_bits, self.n, False)
        i += pi
    
        return (z2, z3, z4)

    def byte_keygen(self):
        """(API) Key pair generation directly into bytes."""
        sk, vk = self.keygen()
        return self.encode_vk(vk), self.encode_sk(sk)

    def byte_verify(self, msg, sm, vk_b):
        """Detached Signature verification directly from bytes."""
        vk, tr, _ = self.decode_vk(vk_b)
        sig = self.decode_sig(sm)
        return self.verify_msg(vk, tr, msg, sig)

    def prove_signature_existence_bytes(self, vk_b, msg, sig_b):
        """
        Produce a lazer proof of signature existence from encoded signature and vk.
        """
        vk, tr, _ = self.decode_vk(vk_b)
        sig = self.decode_sig(sig_b)
        proof = self.prove_signature_existence(vk, tr, msg, sig)
        return proof

    def verify_signature_existence_bytes(self, vk_b, msg, proof, sig_b=None):
        """
        Verify a lazer proof of signature existence from encoded vk.
        """
        vk, tr, _ = self.decode_vk(vk_b)
        result = self.verify_signature_existence(vk, tr, msg, proof)
        return result

### Instantiate Parameter sets

############################
### 128 bits of security ###
############################

plover_128_1  = NIST_PloverSign(  bitsec=128, q=PLOVERSIGN_Q, logdivide=40, 
                n=PLOVERSIGN_N,
                sigma_sk=2**15, sigma_sx=2**37.5, sigma_ux=2, sigma_rnd=2**37.5, B=2**46.2)

plover_all = [
    plover_128_1,
]

if __name__ == "__main__":

    p_test = plover_128_1

    sk, vk = p_test.keygen()
    vk_b = p_test.encode_vk(vk)
    sk_b = p_test.encode_sk(sk)

    # check vk encoding
    vk2, tr, _ = p_test.decode_vk(p_test.encode_vk(vk))
    assert(vk == vk2)

    # check sk encoding
    sk2, _, _ = p_test.decode_sk(p_test.encode_sk(sk))
    assert(sk2[0] == sk[0]) # eq of t

    assert(sk2[1] == sk[1]) # eq s

    # check blind signing
    msg = bytes(range(3))

    print("=== Threshold Keygen ===")
    T = 16
    N = 16

    start_tkeygen = time.time()
    sks, vk = p_test.keygen(T, N)
    end_tkeygen = time.time()
    tkeygen_time = end_tkeygen - start_tkeygen

    tr = bytes(range(p_test.tr_sz))
    msg = bytes(range(3))

    print("=== Threshold Blind Sign ===")
    start_tsign_user = time.time()
    st_u, pm_u = p_test.sign_user_init(vk, tr, msg)
    end_tsign_user = time.time()
    tuser_init_time = end_tsign_user - start_tsign_user

    st_s = [None] * T
    pm_s1 = [None] * T
    start_tsign_server1 = time.time()
    for i in range(T):
        st_s[i], pm_s1[i] = p_test.sign_server1(sks[i], pm_u, list(range(1, T+1)))
    end_tsign_server1 = time.time()
    tserver1_time = end_tsign_server1 - start_tsign_server1

    pm_s2 = [None] * T
    start_tsign_server2 = time.time()
    for i in range(T):
        st_s[i], pm_s2[i] = p_test.sign_server2(sks[i], st_s[i], pm_s1)
    end_tsign_server2 = time.time()
    tserver2_time = end_tsign_server2 - start_tsign_server2

    pm_s3 = [None] * T
    start_tsign_server3 = time.time()
    for i in range(T):
        pm_s3[i] = p_test.sign_server3(sks[i], tr, st_s[i], pm_s2)
    end_tsign_server3 = time.time()
    tserver3_time = end_tsign_server3 - start_tsign_server3

    start_tsign_agg = time.time()
    pm_s = p_test.sign_server_aggregate(pm_s2, pm_s3)
    end_tsign_agg = time.time()
    tserver_agg_time = end_tsign_agg - start_tsign_agg

    start_tsign_user_final = time.time()
    sig = p_test.sign_user_final(tr, st_u, pm_s)
    end_tsign_user_final = time.time()
    tuser_final_time = end_tsign_user_final - start_tsign_user_final

    print("=== Verify ===")
    start_tverify = time.time()
    rsp = p_test.verify_msg(vk, tr, msg, sig)
    end_tverify = time.time()
    tverify_time = end_tverify - start_tverify
    print(rsp)
    assert(rsp is True)

    start_tproof = time.time()
    proof = p_test.prove_signature_existence(vk, tr, msg, sig)
    end_tproof = time.time()
    tproof_time = end_tproof - start_tproof

    start_tproof_verify = time.time()
    assert(p_test.verify_signature_existence(vk, tr, msg, proof) is True)
    end_tproof_verify = time.time()
    tproof_verify_time = end_tproof_verify - start_tproof_verify

    # === Average proof measurements over multiple runs ===
    num_proof_runs = 30
    print(f"\n=== Averaging proof measurements over {num_proof_runs} runs ===")
    
    proof_times = []
    verify_times = []
    
    for i in range(num_proof_runs):
        # Measure proof generation
        start_proof = time.time()
        proof = p_test.prove_signature_existence(vk, tr, msg, sig)
        end_proof = time.time()
        proof_times.append(end_proof - start_proof)
        
        # Measure proof verification
        start_verify = time.time()
        assert(p_test.verify_signature_existence(vk, tr, msg, proof) is True)
        end_verify = time.time()
        verify_times.append(end_verify - start_verify)
    
    # Calculate averages and standard deviations
    avg_proof_time = sum(proof_times) / len(proof_times)
    avg_verify_time = sum(verify_times) / len(verify_times)
    
    def std_dev(values):
        if len(values) <= 1:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5
    
    std_proof_time = std_dev(proof_times)
    std_verify_time = std_dev(verify_times)

    print(f"Threshold keygen time: {tkeygen_time:.6f} seconds")
    print(f"Threshold user init time: {tuser_init_time:.6f} seconds")
    print(f"Threshold server1 time (all): {tserver1_time:.6f} seconds")
    print(f"Threshold server2 time (all): {tserver2_time:.6f} seconds")
    print(f"Threshold server3 time (all): {tserver3_time:.6f} seconds")
    print(f"Threshold server aggregate time: {tserver_agg_time:.6f} seconds")
    print(f"Threshold user final time: {tuser_final_time:.6f} seconds")
    print(f"Threshold verify time: {tverify_time:.6f} seconds")
    print(f"Threshold proof time (single): {tproof_time:.6f} seconds")
    print(f"Threshold proof verify time (single): {tproof_verify_time:.6f} seconds")
    print(f"Threshold proof time (avg ± std): {avg_proof_time:.6f} ± {std_proof_time:.6f} seconds")
    print(f"Threshold proof verify time (avg ± std): {avg_verify_time:.6f} ± {std_verify_time:.6f} seconds")
