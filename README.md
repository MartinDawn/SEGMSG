# SecMsg - Secure Messaging Protocol (Educational)

**SecMsg** là một dự án triển khai giao thức nhắn tin bảo mật Peer-to-Peer (P2P) nhằm mục đích học tập và nghiên cứu các nguyên lý cốt lõi của Mật mã học (Cryptography) và An ninh mạng.

Dự án được xây dựng theo lộ trình học tập "Cybersecurity Roadmap", tập trung vào việc chuyển đổi lý thuyết toán học thành mã nguồn thực tế.

---

## 🏗 Kiến trúc & Tính năng (Phiên bản v0.1 - Tháng 2)

Hiện tại, ứng dụng đã triển khai các nguyên thủy mật mã sau:

* **Ngôn ngữ:** Python 3.x (Standard Library only + Custom Crypto implementations).
* **Giao thức mạng:** TCP Sockets.
* **Trao đổi khóa (Key Exchange):** Diffie-Hellman (Group 14 - 2048 bit).
* **Mã hóa (Confidentiality):** AES-128 chế độ CTR (Counter Mode).
* **Toàn vẹn (Integrity):** HMAC-SHA256 theo mô hình *Encrypt-then-MAC*.
* **Dẫn xuất khóa (KDF):** HKDF (HMAC-based Key Derivation Function) để tách khóa AES và khóa HMAC từ Shared Secret.

---

# 🛡 Threat Model & Security Assessment (Mô hình Đe dọa)

* **Ngày đánh giá:** 08/02/2026
* **Phiên bản đánh giá:** v0.1
* **Phương pháp:** STRIDE & OWASP Top 10

Mục này phân tích các lỗ hổng bảo mật hiện hữu trong mã nguồn v0.1 để định hướng cho việc nâng cấp trong v0.2.

## 1. Sơ đồ Luồng dữ liệu (Data Flow Diagram)

Biểu đồ dưới đây minh họa luồng dữ liệu và ranh giới tin cậy (Trust Boundary).

```mermaid
graph LR
    User((User)) -->|Plaintext| App[SecMsg Client]
    
    subgraph "Trust Zone: Local Machine"
        App -->|Encryption| AES[AES-CTR Module]
        AES -->|Signing| HMAC[HMAC Module]
    end
    
    HMAC -->|Ciphertext + Tag| Socket[Network Socket]
    
    subgraph "DANGER ZONE: Internet/Network"
        Socket -.->|Insecure Channel| Attacker[Man-in-the-Middle?]
        Attacker -.->|Insecure Channel| SocketPeer[Peer Socket]
    end
    
    SocketPeer -->|Verify| HMACVerify[HMAC Verification]
    HMACVerify -->|Decryption| AESDecrypt[AES Decrypt]
    AESDecrypt -->|Plaintext| UserPeer((Peer User))

    style Attacker fill:#f96,stroke:#333,stroke-width:2px
    style Socket fill:#ff9,stroke:#333
    style SocketPeer fill:#ff9,stroke:#333