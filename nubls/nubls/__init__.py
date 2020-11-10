from nubls_wrapper import *

def hash_message(message: bytes, DST: bytes = None) -> bytes:
    from hashlib import sha256
    from py_ecc.bls.hash import i2osp
    from py_ecc.bls.hash_to_curve import hash_to_G2
    from py_ecc.bls.point_compression import compress_G2

    DST = DST or b''    # TODO: Use a valid DST
    mapped_msg = hash_to_G2(message, DST, sha256)
    z1, z2 = compress_G2(mapped_msg)
    return i2osp(z1, 48) + i2osp(z2, 48)
