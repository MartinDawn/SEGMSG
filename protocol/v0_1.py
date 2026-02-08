import time
import hashlib
import struct
from datetime import datetime
from enum import Enum
from AES.AES import ctr_encrypt, ctr_decrypt
from HMAC.HMAC import my_hmac_sha256
from Diffie_Hellman import DH

class MessageType(Enum):
    REGULAR_MESSAGE = 0x01
    HANDSHAKE_REQUEST = 0x02  
    HANDSHAKE_RESPONSE = 0x03 

class SegMessage:
    PROTOCOL_ID = b"SegMSG"

    def __init__(self, message_type: MessageType, payload: bytes, timestamp=None):
        self.message_type = message_type
        self.payload = payload
        self.timestamp = timestamp if timestamp else int(time.time())

    @classmethod
    def create_regular_message(cls, message_text: str):
        return cls(MessageType.REGULAR_MESSAGE, message_text.encode('utf-8'))

    @classmethod
    def create_handshake_request(cls, my_public_key_bytes: bytes):
        return cls(MessageType.HANDSHAKE_REQUEST, my_public_key_bytes)

    @classmethod
    def create_handshake_response(cls, my_public_key_bytes: bytes):
        return cls(MessageType.HANDSHAKE_RESPONSE, my_public_key_bytes)

    @staticmethod
    def inspect_packet(raw_bytes: bytes):
        try:
            
            if len(raw_bytes) < 51 + 32: # Min header size
                return f"Packet too short to inspect ({len(raw_bytes)} bytes)"

            cursor = 0
            
            # 1. Protocol ID
            proto_id = raw_bytes[cursor:cursor+6]
            cursor += 6
            
            # 2. Message Type
            msg_type_val = raw_bytes[cursor]
            try:
                msg_type_str = MessageType(msg_type_val).name
            except:
                msg_type_str = f"UNKNOWN ({msg_type_val})"
            cursor += 1
            
            # 3. Length
            length = int.from_bytes(raw_bytes[cursor:cursor+4], 'big')
            cursor += 4
            
            # 4. Original Hash
            org_hash = raw_bytes[cursor:cursor+32]
            cursor += 32
            
            # 5. Timestamp
            ts_int = int.from_bytes(raw_bytes[cursor:cursor+8], 'big')
            try:
                ts_str = datetime.fromtimestamp(ts_int).strftime('%Y-%m-%d %H:%M:%S')
            except:
                ts_str = f"Invalid TS ({ts_int})"
            cursor += 8
            
            # 6. Encrypted Payload
            payload_enc = raw_bytes[cursor:cursor+length]
            cursor += length
            
            # 7. HMAC
            hmac_val = raw_bytes[cursor:cursor+32]
            
            # --- Format Output String ---
            info =  f"╔══ PACKET INSPECTION ({len(raw_bytes)} bytes) ══\n"
            info += f"╠═ Protocol ID   : {proto_id.decode('utf-8', errors='replace')}\n"
            info += f"╠═ Type          : {msg_type_str} (0x{msg_type_val:02x})\n"
            info += f"╠═ Payload Len   : {length} bytes\n"
            info += f"╠═ Original Hash : {org_hash.hex()}\n"
            info += f"╠═ Timestamp     : {ts_str} (Raw: {ts_int})\n"
            info += f"╠═ PAYLOAD (Hex) : {payload_enc.hex()}\n"
            info += f"╚═ HMAC (32B)    : {hmac_val.hex()}"
            
            return info
        except Exception as e:
            return f"Error inspecting packet: {e}"

    # --- Giữ nguyên logic to_bytes và from_bytes cũ ---
    def to_bytes(self, aes_key=None, hmac_key=None) -> bytes:
        payload_to_send = self.payload
        if self.message_type == MessageType.REGULAR_MESSAGE:
            if not aes_key: raise ValueError("Missing AES key")
            payload_to_send = ctr_encrypt(aes_key, b"\x00"*8, self.payload)

        original_payload_hash = hashlib.sha256(self.payload).digest()
        length = len(payload_to_send)
        
        message_without_hmac = (
            self.PROTOCOL_ID +
            self.message_type.value.to_bytes(1, 'big') +
            length.to_bytes(4, 'big') +
            original_payload_hash + 
            self.timestamp.to_bytes(8, 'big') +
            payload_to_send
        )

        if hmac_key:
            message_hmac = my_hmac_sha256(hmac_key, message_without_hmac)
        else:
            message_hmac = b'\x00' * 32 

        return message_without_hmac + message_hmac

    @classmethod
    def from_bytes(cls, raw_bytes: bytes, aes_key=None, hmac_key=None):
        HMAC_SIZE = 32
        if len(raw_bytes) < HMAC_SIZE + 51: 
            raise ValueError("Data too short")

        message_part = raw_bytes[:-HMAC_SIZE]
        received_hmac = raw_bytes[-HMAC_SIZE:]

        if hmac_key:
            calculated_hmac = my_hmac_sha256(hmac_key, message_part)
            if received_hmac != calculated_hmac:
                raise ValueError("HMAC validation failed!")
        
        if not message_part.startswith(cls.PROTOCOL_ID):
             raise ValueError("Invalid protocol ID")

        message_type_val = int.from_bytes(message_part[6:7], 'big')
        message_type = MessageType(message_type_val)
        length = int.from_bytes(message_part[7:11], 'big')
        received_original_hash = message_part[11:43]
        timestamp = int.from_bytes(message_part[43:51], 'big')
        
        payload_part = message_part[51:51+length]
        final_payload = payload_part
        
        if message_type == MessageType.REGULAR_MESSAGE:
            if not aes_key: raise ValueError("Missing AES key")
            final_payload = ctr_decrypt(aes_key, b"\x00" * 8, payload_part)
        
        if hashlib.sha256(final_payload).digest() != received_original_hash:
             raise ValueError("Payload hash mismatch!")
        
        return cls(message_type, final_payload, timestamp)