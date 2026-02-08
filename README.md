# SecMsg - Secure P2P Messaging Protocol

A cryptographically-secured peer-to-peer messaging system that enables secure, authenticated communication between two peers over a network. This project implements a custom protocol with end-to-end encryption, message authentication, and perfect forward secrecy.

## Features

- **End-to-End Encryption**: All messages encrypted with AES-128-CTR mode
- **Message Authentication**: HMAC-SHA256 ensures message integrity and authenticity
- **Secure Key Exchange**: Diffie-Hellman (2048-bit MODP Group 14) for establishing shared secrets
- **Multi-Peer Support**: Handles multiple concurrent peer connections
- **GUI Application**: Tkinter-based secure chat interface with protocol inspection
- **Protocol Transparency**: Detailed packet inspection for debugging and verification
- **Custom Crypto Implementation**: Educational implementations of cryptographic primitives

## Project Structure

```
SecMsg/
├── chat_gui.py                          # Tkinter GUI application for secure chat
├── peer/
│   └── peer.py                          # Core peer networking and protocol handling
├── protocol/
│   └── v0_1.py                          # SegMessage protocol definition
├── AES/
│   └── AES.py                           # AES-128 encryption with CTR mode
├── Diffie_Hellman/
│   └── DH.py                            # Diffie-Hellman key exchange
├── HMAC/
│   ├── HMAC.py                          # HMAC-SHA256 implementation
│   └── hmac_key_generation.py           # HKDF key derivation
└── key_local_storage/                   # Local storage for key material
    ├── peer1.txt
    └── peer2.txt
```

## Technologies Used

- **Language**: Python 3
- **Cryptography**:
  - AES-128-CTR (symmetric encryption)
  - HMAC-SHA256 (message authentication)
  - Diffie-Hellman Key Exchange (asymmetric key agreement)
- **GUI Framework**: Tkinter
- **Networking**: Python socket library
- **Architecture**: Multi-threaded peer-to-peer model

## How It Works

### 1. Key Exchange (Handshake Phase)
- Peer A connects to Peer B
- Both peers generate Diffie-Hellman private keys
- Public keys are exchanged via `HANDSHAKE_REQUEST` and `HANDSHAKE_RESPONSE` messages
- Shared secret is calculated using Diffie-Hellman key agreement
- AES key is derived from the shared secret
- HMAC key is derived using HKDF (HMAC-based Key Derivation Function)

### 2. Message Exchange
- Messages are encrypted using AES-128-CTR mode
- HMAC-SHA256 is computed over the complete message for authentication
- Timestamps are included for data freshness
- Messages are transmitted with protocol headers and payload validation

### 3. Protocol Structure
Each message contains:
- Protocol ID and Message Type
- Payload length and original hash
- Timestamp
- Encrypted payload (AES-CTR)
- HMAC-SHA256 authentication tag

## Getting Started

### Requirements
- Python 3.x
- No external dependencies (all cryptographic implementations are included)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd SecMsg
```

2. Run the GUI application:
```bash
python chat_gui.py
```

## Usage

### GUI Application

1. **Start the Application**: Run `python chat_gui.py`
2. **Configure Server**: Set the listening port (default: 5000)
3. **Connect to Peer**: Enter the peer's IP address and port, then click "Connect"
4. **Send Messages**: Type your message and press "Send" to encrypt and transmit
5. **Monitor Protocol**: View detailed packet inspection including encryption status and HMAC validation

### Message Types

- **HANDSHAKE_REQUEST (0x02)**: Initiates key exchange with public key
- **HANDSHAKE_RESPONSE (0x03)**: Responds to key exchange with public key
- **REGULAR_MESSAGE (0x01)**: Encrypted chat message with authentication

## Security Considerations

### Strengths
- **Perfect Forward Secrecy**: Ephemeral DH key exchange ensures old sessions cannot be decrypted
- **Authenticated Encryption**: HMAC-SHA256 prevents message tampering
- **Strong Symmetric Encryption**: AES-128-CTR mode provides confidentiality
- **2048-bit DH**: Cryptographically strong key exchange parameter

### Educational Focus
This project is designed for learning cryptography and secure network programming concepts. While the implementations are functionally correct, for production use consider:
- Using established cryptographic libraries (cryptography, PyCryptodome)
- Implementing additional security features (perfect forward secrecy per-message, replay attack prevention)
- Security audits and formal verification

## Architecture Overview

```
┌─────────────────┐           Network           ┌─────────────────┐
│   Peer A        │ ◄──────────────────────────► │   Peer B        │
│  (chat_gui.py)  │                              │  (chat_gui.py)  │
└────────┬────────┘                              └────────┬────────┘
         │                                                 │
         │                                                 │
    ┌────▼─────────────────────────────────────────────────▼─────┐
    │  Protocol Layer (v0_1.py)                                   │
    │  - Message serialization/deserialization                    │
    │  - Protocol validation                                      │
    └────┬─────────────────────────────────────────────────┬──────┘
         │                                                 │
    ┌────▼──────────────┐                          ┌──────▼────────┐
    │ Encryption Layer  │                          │ Encryption    │
    │ ┌──────────────┐  │                          │ Layer         │
    │ │ AES-128-CTR  │  │                          │ ┌──────────┐  │
    │ │ HMAC-SHA256  │  │                          │ │ AES-CTR  │  │
    │ └──────────────┘  │                          │ │ HMAC-SHA │  │
    └────┬──────────────┘                          └──────┬────────┘
         │                                                 │
    ┌────▼──────────────┐                          ┌──────▼────────┐
    │ Key Exchange (DH) │                          │ Key Exchange  │
    │ Shared Secret     │                          │ Shared Secret │
    └───────────────────┘                          └───────────────┘
```

## File Descriptions

| File | Purpose |
|------|---------|
| `chat_gui.py` | Main GUI application - handles user interface and peer connections |
| `peer/peer.py` | Core networking logic - socket management and protocol handling |
| `protocol/v0_1.py` | Protocol definition - message types and packet structure |
| `AES/AES.py` | AES-128 implementation with ECB and CTR modes |
| `Diffie_Hellman/DH.py` | Diffie-Hellman key exchange implementation |
| `HMAC/HMAC.py` | HMAC-SHA256 implementation (RFC 2104) |
| `HMAC/hmac_key_generation.py` | HKDF-based key derivation |

## Contributing

Contributions are welcome! Please feel free to:
- Report bugs and security issues
- Suggest improvements
- Submit pull requests with enhancements

## License

[Specify your license here]

## Disclaimer

This is an educational project created to demonstrate cryptographic concepts and secure peer-to-peer communication. While the implementations are correct, this is not recommended for production use in security-critical applications without professional security review.

## Author

[Your name/team]

## References

- RFC 3526: More Modular Exponential (MODP) Diffie-Hellman groups for use in IETF protocols
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
- NIST AES Standard (FIPS 197)
- HKDF: HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)
