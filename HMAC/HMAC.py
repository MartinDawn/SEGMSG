import hashlib

def my_hmac_sha256(key: bytes, message: bytes) -> bytes:

    hash_func = hashlib.sha256
    block_size = hash_func().block_size  

    if len(key) > block_size:
        key = hash_func(key).digest()
    
    if len(key) < block_size:
        key = key.ljust(block_size, b'\x00')


    opad = bytes([0x5c] * block_size)
    ipad = bytes([0x36] * block_size)

    o_key_pad = bytes(k ^ p for k, p in zip(key, opad))
    i_key_pad = bytes(k ^ p for k, p in zip(key, ipad))


    # H( (K' ⊕ ipad) || m )
    inner_hash = hash_func(i_key_pad + message).digest()
    
    # H( (K' ⊕ opad) || inner_hash )
    outer_hash = hash_func(o_key_pad + inner_hash).digest()

    return outer_hash

if __name__ == "__main__":
    import hmac

    secret_key = b'mysecretkey'
    msg = b'Hello HMAC, this is a test message.'

    my_result = my_hmac_sha256(secret_key, msg)
    print(f"Kết quả của hàm tự viết: {my_result.hex()}")

    official_result = hmac.new(secret_key, msg, hashlib.sha256).digest()
    print(f"Kết quả của thư viện hmac: {official_result.hex()}")

    # Xác minh hai kết quả giống hệt nhau
    assert my_result == official_result
    print("\nXác minh thành công! Hai kết quả trùng khớp.")