
def encode_bits(v, bits):
    """Encode vector v of integers into bytes, 'bits' per element."""
    x = 0                           # bit buffer
    l = 0                           # number of bits in x
    i = 0                           # index in vector v[i]
    b = b''                         # zero-length array of bytes
    m = (1 << bits) - 1             # bit mask

    while i < len(v):
        while l < 8 and i < len(v):
            x |= (v[i] & m) << l    # load an integer into x
            i += 1
            l += bits
        while l >= 8:
            b += bytes([x & 0xFF])  # store a bytes from x
            x >>= 8
            l -= 8
    if l > 0:
        b += bytes([x])             # a byte with leftover bits

    return b


"""
#   this is functionally equivalent but slower -- O(n^2)!
def encode_bits(v, bits):
    x = 0                   # bit buffer
    m = (1 << bits) - 1     # bit mask; "bits" ones
    for i in range(len(v)):
        x |= (v[i] & m) << (bits * i)
    return x.to_bytes( (bits * len(v) + 7) // 8, byteorder='little' )
"""

def decode_bits(b, bits, n, is_signed=False):
    """
    Decode bytes from 'b' into a vector of 'n' integers, 'bits' each.
    """
    x = 0                           # bit buffer
    i = 0                           # source byte index b[i]
    v = []                          # zero-length result vector
    l = 0                           # number of bits in x

    if is_signed:
        s = 1 << (bits - 1)         # sign bit is negative
        m = s - 1                   # mask bits-1 bits
    else:
        s = 0                       # unsigned: no sign bit
        m = (1 << bits) - 1         # mask given number of bits

    while len(v) < n:
        while l < bits:             # read bytes until full integer
            x |= int(b[i]) << l
            i += 1
            l += 8
        while l >= bits and len(v) < n: # write integer(s)
            v += [ (x & m) - (x & s) ]
            x >>= bits
            l -= bits

    return v, i     #   return the vector and number of bytes read
