import time
from enum import Enum
import tink
from tink import aead

class MessageType(Enum):
    REGULAR_MESSAGE = 0x01
    HANDSHAKE_REQUEST = 0x02  
    HANDSHAKE_RESPONSE = 0x03 

class SegMessage:
    PROTOCOL_ID = b"SegMSG"

    def __init__(self, message_type: MessageType, payload: bytes, timestamp=None):
        self.message_type = message_type
        self.payload = payload
        # [TINK] KHÔNG CÒN self.nonce. Tink tự động chèn 12-byte nonce vào đầu bản mã.
        self.timestamp = timestamp if timestamp else int(time.time())

    @classmethod
    def create_regular_message(cls, message_text: str):
        return cls(MessageType.REGULAR_MESSAGE, message_text.encode('utf-8'))

    @classmethod
    def create_handshake_request(cls, payload_bytes: bytes):
        return cls(MessageType.HANDSHAKE_REQUEST, payload_bytes)

    @classmethod
    def create_handshake_response(cls, payload_bytes: bytes):
        return cls(MessageType.HANDSHAKE_RESPONSE, payload_bytes)

    @staticmethod
    def inspect_packet(raw_bytes: bytes):
        try:
            min_len = 6 + 1 + 4 + 8 # [ID:6] + [Type:1] + [Len:4] + [Time:8] = 19
            if len(raw_bytes) < min_len:
                return f"Packet too short ({len(raw_bytes)} bytes)"

            cursor = 0
            proto_id = raw_bytes[cursor:cursor+6]; cursor += 6
            msg_type_val = raw_bytes[cursor]; cursor += 1
            try: msg_type_str = MessageType(msg_type_val).name
            except: msg_type_str = f"UNKNOWN ({msg_type_val})"
            
            length = int.from_bytes(raw_bytes[cursor:cursor+4], 'big'); cursor += 4
            ts_int = int.from_bytes(raw_bytes[cursor:cursor+8], 'big'); cursor += 8

            tink_payload = raw_bytes[cursor:cursor+length]

            info =  f"╔══ PACKET INSPECTION (GOOGLE TINK AEAD) ══\n"
            info += f"╠═ Type      : {msg_type_str}\n"
            info += f"╠═ Timestamp : {ts_int}\n"
            info += f"╚═ Tink Blob : {tink_payload.hex()} (Contains Header, Nonce, Ciphertext, Tag)"
            return info
        except Exception as e:
            return f"Error inspecting: {e}"

    def to_bytes(self, tink_aead_primitive=None) -> bytes:
        header_aad = (
            self.PROTOCOL_ID +
            self.message_type.value.to_bytes(1, 'big') +
            self.timestamp.to_bytes(8, 'big')
        )

        payload_to_send = self.payload

        if self.message_type == MessageType.REGULAR_MESSAGE:
            if not tink_aead_primitive: raise ValueError("Missing Tink AEAD primitive")
            
            payload_to_send = tink_aead_primitive.encrypt(self.payload, header_aad)

        length = len(payload_to_send)
        return (
            self.PROTOCOL_ID +
            self.message_type.value.to_bytes(1, 'big') +
            length.to_bytes(4, 'big') +
            self.timestamp.to_bytes(8, 'big') +
            payload_to_send
        )

    @classmethod
    def from_bytes(cls, raw_bytes: bytes, tink_aead_primitive=None):
        min_len = 19
        if len(raw_bytes) < min_len: raise ValueError("Data too short")

        cursor = 0
        if raw_bytes[0:6] != cls.PROTOCOL_ID: raise ValueError("Invalid ID")
        cursor += 6

        message_type = MessageType(raw_bytes[cursor]); cursor += 1
        length = int.from_bytes(raw_bytes[cursor:cursor+4], 'big'); cursor += 4
        timestamp = int.from_bytes(raw_bytes[cursor:cursor+8], 'big'); cursor += 8

        payload_part = raw_bytes[cursor:cursor+length]
        final_payload = payload_part

        header_aad = (
            cls.PROTOCOL_ID +
            message_type.value.to_bytes(1, 'big') +
            timestamp.to_bytes(8, 'big')
        )

        if message_type == MessageType.REGULAR_MESSAGE:
            if not tink_aead_primitive: raise ValueError("Missing Tink AEAD primitive")
            try:
                final_payload = tink_aead_primitive.decrypt(payload_part, header_aad)
            except tink.TinkError:
                raise ValueError("Decryption Failed! (Invalid Key, Corrupt Data, or Bad AAD)")

        return cls(message_type, final_payload, timestamp)