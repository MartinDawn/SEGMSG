import os
import time
import struct
from datetime import datetime
from enum import Enum

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MessageType(Enum):
    REGULAR_MESSAGE = 0x01
    HANDSHAKE_REQUEST = 0x02  
    HANDSHAKE_RESPONSE = 0x03 

class SegMessage:
    PROTOCOL_ID = b"SegMSG"
    NONCE_SIZE = 12 
    TAG_SIZE = 16   

    def __init__(self, message_type: MessageType, payload: bytes, nonce: bytes = None, timestamp=None):
        self.message_type = message_type
        self.payload = payload
        self.nonce = nonce if nonce else os.urandom(self.NONCE_SIZE)
        self.timestamp = timestamp if timestamp else int(time.time())

    @classmethod
    def create_regular_message(cls, message_text: str):
        return cls(MessageType.REGULAR_MESSAGE, message_text.encode('utf-8'))

    @classmethod
    def create_handshake_request(cls, public_key_bytes: bytes):
        return cls(MessageType.HANDSHAKE_REQUEST, public_key_bytes)

    @classmethod
    def create_handshake_response(cls, public_key_bytes: bytes):
        return cls(MessageType.HANDSHAKE_RESPONSE, public_key_bytes)

    # --- INSPECTOR CHO AES-GCM ---
    @staticmethod
    def inspect_packet(raw_bytes: bytes):
        try:
            min_len = 6 + 1 + 12 + 4 + 8 # Header size
            if len(raw_bytes) < min_len:
                return f"Packet too short ({len(raw_bytes)} bytes)"

            cursor = 0
            proto_id = raw_bytes[cursor:cursor+6]; cursor += 6
            
            msg_type_val = raw_bytes[cursor]; cursor += 1
            try: msg_type_str = MessageType(msg_type_val).name
            except: msg_type_str = f"UNKNOWN ({msg_type_val})"

            nonce = raw_bytes[cursor:cursor+12]; cursor += 12
            
            length = int.from_bytes(raw_bytes[cursor:cursor+4], 'big'); cursor += 4
            
            ts_int = int.from_bytes(raw_bytes[cursor:cursor+8], 'big'); cursor += 8
            try: ts_str = datetime.fromtimestamp(ts_int).strftime('%H:%M:%S')
            except: ts_str = str(ts_int)

            # Ciphertext + Tag
            cipher_data = raw_bytes[cursor:]
            
            # 16 byte Auth Tag
            tag = cipher_data[-16:] if len(cipher_data) >= 16 else b''
            ciphertext_body = cipher_data[:-16] if len(cipher_data) >= 16 else cipher_data

            info =  f"╔══ PACKET INSPECTION (AES-GCM) ══\n"
            info += f"╠═ Type      : {msg_type_str}\n"
            info += f"╠═ Nonce (IV): {nonce.hex()}\n"
            info += f"╠═ Timestamp : {ts_str}\n"
            info += f"╠═ Ciphertext: {ciphertext_body.hex()}\n"
            info += f"╚═ Auth Tag  : {tag.hex()}"
            return info
        except Exception as e:
            return f"Error inspecting: {e}"

    def to_bytes(self, aes_key=None) -> bytes:
        payload_to_send = self.payload

        header_bytes = (
            self.PROTOCOL_ID +
            self.message_type.value.to_bytes(1, 'big') +
            self.nonce +
            self.timestamp.to_bytes(8, 'big')
        )

        if self.message_type == MessageType.REGULAR_MESSAGE:
            if not aes_key: raise ValueError("Missing AES key")
            aesgcm = AESGCM(aes_key)
            payload_to_send = aesgcm.encrypt(self.nonce, self.payload, header_bytes)

        length = len(payload_to_send)
        return (
            self.PROTOCOL_ID +
            self.message_type.value.to_bytes(1, 'big') +
            self.nonce +
            length.to_bytes(4, 'big') + 
            self.timestamp.to_bytes(8, 'big') +
            payload_to_send
        )

    @classmethod
    def from_bytes(cls, raw_bytes: bytes, aes_key=None):
        min_len = 6 + 1 + 12 + 4 + 8
        if len(raw_bytes) < min_len: raise ValueError("Data too short")

        cursor = 0
        if raw_bytes[0:6] != cls.PROTOCOL_ID: raise ValueError("Invalid ID")
        cursor += 6

        msg_type_val = raw_bytes[cursor]; cursor += 1
        message_type = MessageType(msg_type_val)

        nonce = raw_bytes[cursor:cursor+12]; cursor += 12
        length = int.from_bytes(raw_bytes[cursor:cursor+4], 'big'); cursor += 4
        timestamp = int.from_bytes(raw_bytes[cursor:cursor+8], 'big'); cursor += 8

        payload_part = raw_bytes[cursor:cursor+length]

        final_payload = payload_part

        header_aad = (
            cls.PROTOCOL_ID +
            message_type.value.to_bytes(1, 'big') +
            nonce +
            timestamp.to_bytes(8, 'big')
        )

        if message_type == MessageType.REGULAR_MESSAGE:
            if not aes_key: raise ValueError("Missing AES key")
            try:
                aesgcm = AESGCM(aes_key)
                final_payload = aesgcm.decrypt(nonce, payload_part, header_aad)
            except Exception:
                raise ValueError("Decryption Failed! (Invalid Tag or Key)")

        return cls(message_type, final_payload, nonce, timestamp)