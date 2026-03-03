import os
import tink
from tink import aead, signature, hybrid, cleartext_keyset_handle

# 1. Đăng ký các Primitives (Tính năng) của Tink mà chúng ta sẽ dùng
aead.register()
signature.register()
hybrid.register()

def generate_keys_for_peer(port):
    os.makedirs("tink_keys", exist_ok=True)

    sig_template = signature.signature_key_templates.ECDSA_P256
    sig_priv_handle = tink.new_keyset_handle(sig_template)
    sig_pub_handle = sig_priv_handle.public_keyset_handle()
    
    hyb_template = hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
    hyb_priv_handle = tink.new_keyset_handle(hyb_template)
    hyb_pub_handle = hyb_priv_handle.public_keyset_handle()
    
    # Hàm ghi Keyset ra file JSON
    def write_keyset(handle, filename):
        with open(filename, 'wt') as f:
            cleartext_keyset_handle.write(tink.JsonKeysetWriter(f), handle)

    # Lưu 4 file cho mỗi Peer
    write_keyset(sig_priv_handle, f"tink_keys/peer{port}_sig_priv.json")
    write_keyset(sig_pub_handle, f"tink_keys/peer{port}_sig_pub.json")
    write_keyset(hyb_priv_handle, f"tink_keys/peer{port}_hyb_priv.json")
    write_keyset(hyb_pub_handle, f"tink_keys/peer{port}_hyb_pub.json")
    
    print(f"[+] Đã tạo thành công bộ khóa Tink cho Port {port}")

if __name__ == "__main__":
    print("--- Khởi tạo hạ tầng Google Tink ---")
    generate_keys_for_peer(5000)
    generate_keys_for_peer(5001)
    print("--- Hoàn tất! Khóa nằm trong thư mục 'tink_keys/' ---")