import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key_cert(name, filename_prefix, is_ca=False, ca_cert=None, ca_key=None):
    # 1. Tạo Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096 if is_ca else 2048,
    )

    # 2. Thông tin chủ sở hữu
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecMsg Project"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    # 3. Builder
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject if ca_cert else subject)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))

    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    else:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    # 4. Ký (Sign)
    signing_key = ca_key if ca_key else private_key
    certificate = builder.sign(
        private_key=signing_key, algorithm=hashes.SHA256(),
    )

    # 5. Lưu file
    if not os.path.exists("pki"):
        os.makedirs("pki")
    
    # Lưu Private Key
    key_path = f"pki/{filename_prefix}.key"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    # Lưu Certificate
    cert_path = f"pki/{filename_prefix}.crt"
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Generated: {key_path}")
    return private_key, certificate

if __name__ == "__main__":
    print("--- Regenerating PKI with Correct Filenames ---")
    
    # 1. Tạo CA
    ca_key, ca_cert = generate_key_cert(
        name=u"SecMsg Root CA", 
        filename_prefix="secmsg_root_ca", 
        is_ca=True
    )

    # 2. Tạo Peer A (Port 5000)
    # Tên file sẽ là: peerA_port5000.key (Khớp với logic tìm kiếm)
    generate_key_cert(
        name=u"PeerA_Port5000", 
        filename_prefix="peerA_port5000", 
        is_ca=False, ca_cert=ca_cert, ca_key=ca_key
    )

    # 3. Tạo Peer B (Port 5001)
    generate_key_cert(
        name=u"PeerB_Port5001", 
        filename_prefix="peerB_port5001", 
        is_ca=False, ca_cert=ca_cert, ca_key=ca_key
    )
    
    # 4. Tạo Peer C (Port 5002 - Cho bài test mở rộng)
    generate_key_cert(
        name=u"PeerC_Port5002", 
        filename_prefix="peerC_port5002", 
        is_ca=False, ca_cert=ca_cert, ca_key=ca_key
    )
    
    print("--- PKI Setup Complete! ---")