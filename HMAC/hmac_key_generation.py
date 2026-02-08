import hmac
import hashlib
import math

def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:

    if salt is None or len(salt) == 0:
        salt = b'\x00' * hashlib.sha256().digest_size
    
    prk = hmac.new(salt, input_key_material, hashlib.sha256).digest()
    return prk

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    hash_len = hashlib.sha256().digest_size # 32 bytes
    num_blocks = math.ceil(length / hash_len)

    if num_blocks > 255:
        raise ValueError("Độ dài khóa yêu cầu quá lớn.")

    output_key = b""
    T = b""
    for i in range(1, num_blocks + 1):
        data_to_hash = T + info + bytes([i])
        T = hmac.new(prk, data_to_hash, hashlib.sha256).digest()
        output_key += T
        
    return output_key[:length]

def derive_key_from_aes_key(
    source_aes_key: bytes, 
    info_string: bytes, 
    derived_key_length: int = 32
) -> bytes:

    prk = hkdf_extract(salt=None, input_key_material=source_aes_key)
    
    derived_key = hkdf_expand(prk, info_string, derived_key_length)
    
    return derived_key