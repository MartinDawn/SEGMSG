import socket
import threading
import io
import tink
from tink import aead, signature, hybrid, cleartext_keyset_handle

aead.register()
signature.register()
hybrid.register()

from protocol.v0_1 import SegMessage, MessageType

class Peer:
    def __init__(self, host='0.0.0.0', port=5000, on_event=None):
        self.host = host
        self.port = port
        self.listen_sock = None
        self.running = False
        self.connections = [] 
        self.peer_states = {} 
        self.on_event = on_event
        
        # Load Private Keys của chính mình
        self._load_my_keys()

    def _load_my_keys(self):
        """Đọc Keyset từ file JSON do Tink sinh ra"""
        def read_keyset(filename):
            with open(filename, 'rt') as f:
                keyset_json = f.read()
                return cleartext_keyset_handle.read(tink.JsonKeysetReader(keyset_json))
        try:
            sig_priv = read_keyset(f"tink_keys/peer{self.port}_sig_priv.json")
            hyb_priv = read_keyset(f"tink_keys/peer{self.port}_hyb_priv.json")
            
            # Khởi tạo các Primitive (Công cụ) trực tiếp từ Keyset
            self.my_signer = sig_priv.primitive(signature.PublicKeySign)
            self.my_hybrid_decrypt = hyb_priv.primitive(hybrid.HybridDecrypt)
            print(f"Loaded Tink Keys for Port {self.port}")
        except Exception as e:
            print(f"CRITICAL: Không thể load Tink keys: {e}")

    def _get_peer_primitives(self, peer_port):
        """Load Public Keys của đối phương để kiểm tra chữ ký và mã hóa"""
        def read_keyset(filename):
            with open(filename, 'rt') as f:
                keyset_json = f.read()
                return cleartext_keyset_handle.read(tink.JsonKeysetReader(keyset_json))
        try:
            sig_pub = read_keyset(f"tink_keys/peer{peer_port}_sig_pub.json")
            hyb_pub = read_keyset(f"tink_keys/peer{peer_port}_hyb_pub.json")
            
            verifier = sig_pub.primitive(signature.PublicKeyVerify)
            hybrid_encryptor = hyb_pub.primitive(hybrid.HybridEncrypt)
            return verifier, hybrid_encryptor
        except Exception as e:
            raise ValueError(f"Không tìm thấy public key của Port {peer_port}: {e}")

    def emit(self, event_type, idx, content):
        if self.on_event: self.on_event(event_type, idx, content)

    def start_listening(self, backlog=5):
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind((self.host, self.port))
        self.listen_sock.listen(backlog)
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        print(f"Peer listening on {self.host}:{self.port}")

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.listen_sock.accept()
                self._add_connection(conn, addr, "in", peer_port=None)
            except: break

    def _add_connection(self, conn, addr, direction, peer_port=None):
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        idx = len(self.connections)
        self.connections.append((conn, addr, direction))
        
        self.peer_states[idx] = {
            'addr': addr,
            'peer_port': peer_port, 
            'aead_primitive': None, # Tink Primitive
            'handshake_complete': False
        }
        
        self.emit("NEW_CONN", idx, f"{addr[0]}:{addr[1]} ({direction})")
        threading.Thread(target=self._recv_loop, args=(idx,), daemon=True).start()
        return idx

    def connect(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            # Lưu lại port của đối phương để biết đường lấy Public Key
            idx = self._add_connection(sock, (host, port), "out", peer_port=port)
            self._send_handshake(idx, msg_type=MessageType.HANDSHAKE_REQUEST) 
        except Exception as e:
            print(f"Error connecting: {e}")

    def _send_handshake(self, idx, msg_type=MessageType.HANDSHAKE_REQUEST):
        state = self.peer_states[idx]
        
        if msg_type == MessageType.HANDSHAKE_REQUEST:
            peer_port = state['peer_port']
            print(peer_port)
            _, peer_hybrid_encrypt = self._get_peer_primitives(peer_port)

            session_keyset = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)
            
            out_stream = io.BytesIO()
            cleartext_keyset_handle.write(tink.BinaryKeysetWriter(out_stream), session_keyset)
            raw_session_key = out_stream.getvalue()

            enc_session_key = peer_hybrid_encrypt.encrypt(raw_session_key, b"handshake_context")

            signature_bytes = self.my_signer.sign(enc_session_key)
            
            payload = (
                self.port.to_bytes(4, 'big') +
                len(enc_session_key).to_bytes(2, 'big') + enc_session_key +
                len(signature_bytes).to_bytes(2, 'big') + signature_bytes
            )
            
            state['aead_primitive'] = session_keyset.primitive(aead.Aead)
            req = SegMessage.create_handshake_request(payload)
            self.emit("LOG", idx, f">>> GỬI TINK HANDSHAKE REQUEST\nĐã tạo AEAD Session Key và mã hóa ECIES.")
            
        else: # RESPONSE
            sig = self.my_signer.sign(b"OK")
            payload = self.port.to_bytes(4, 'big') + sig
            req = SegMessage.create_handshake_response(payload)
            self.emit("LOG", idx, f">>> GỬI TINK HANDSHAKE RESPONSE")
            
        self.connections[idx][0].sendall(req.to_bytes())

    def _recv_loop(self, idx):
        conn = self.connections[idx][0]
        buffer = b""
        HEADER_SIZE = 19
        
        while True:
            try:
                data = conn.recv(8192)
                if not data: break
                buffer += data
                
                while True:
                    if len(buffer) < HEADER_SIZE: break
                    # ID(6) + Type(1) + Len(4) -> Len là 7:11
                    payload_len = int.from_bytes(buffer[7:11], 'big')
                    total_packet_len = HEADER_SIZE + payload_len
                    
                    if len(buffer) < total_packet_len: break
                    
                    packet = buffer[:total_packet_len]
                    buffer = buffer[total_packet_len:]
                    self.handle_data(idx, packet)
            except Exception as e:
                self.emit("LOG", idx, f"Error recv loop: {e}")
                break
        self._close_connection(idx)

    def handle_data(self, idx, data: bytes):
        state = self.peer_states[idx]
        aead_prim = state.get('aead_primitive')

        self.emit("LOG", idx, f"<<< ĐÃ NHẬN GÓI TIN ({len(data)} bytes)")

        try:
            msg = SegMessage.from_bytes(data, tink_aead_primitive=aead_prim)
        except ValueError as e:
            if not state['handshake_complete']:
                try: msg = SegMessage.from_bytes(data, tink_aead_primitive=None)
                except: return
            else:
                self.emit("LOG", idx, f"❌ Lỗi giải mã Tink AEAD: {e}")
                return

        if msg.message_type == MessageType.HANDSHAKE_REQUEST:
            try:
                payload = msg.payload
                
                peer_port = int.from_bytes(payload[0:4], 'big')
                state['peer_port'] = peer_port
                
                enc_len = int.from_bytes(payload[4:6], 'big')
                enc_session_key = payload[6:6+enc_len]
                
                cursor = 6 + enc_len
                sig_len = int.from_bytes(payload[cursor:cursor+2], 'big')
                signature_bytes = payload[cursor+2:cursor+2+sig_len]
                
                print(f"Peer Port from Handshake: {peer_port}")
                peer_verifier, _ = self._get_peer_primitives(peer_port)
                peer_verifier.verify(signature_bytes, enc_session_key)
                self.emit("LOG", idx, f"✔ Đã xác thực chữ ký số Tink của Port {peer_port}")
                
                raw_session_key = self.my_hybrid_decrypt.decrypt(enc_session_key, b"handshake_context")
                
                session_keyset = cleartext_keyset_handle.read(tink.BinaryKeysetReader(raw_session_key))
                state['aead_primitive'] = session_keyset.primitive(aead.Aead)
                state['handshake_complete'] = True
                
                self.emit("LOG", idx, f"*** KẾT NỐI TINK AEAD ĐÃ THIẾT LẬP ***\n(Tự động quản lý Nonce và Tag)")
                
                self._send_handshake(idx, msg_type=MessageType.HANDSHAKE_RESPONSE)

            except tink.TinkError as e:
                self.emit("LOG", idx, f"❌ Lỗi Xác thực / Giải mã: {e}")
                self._close_connection(idx)

        elif msg.message_type == MessageType.HANDSHAKE_RESPONSE:
            try:
                payload = msg.payload
                peer_port = int.from_bytes(payload[0:4], 'big')
                signature_bytes = payload[4:]
                
                peer_verifier, _ = self._get_peer_primitives(peer_port)
                peer_verifier.verify(signature_bytes, b"OK")
                
                state['handshake_complete'] = True
                self.emit("LOG", idx, f"*** KẾT NỐI TINK AEAD ĐÃ THIẾT LẬP ***\n(Tự động quản lý Nonce và Tag)")
            except tink.TinkError as e:
                self.emit("LOG", idx, f"❌ Lỗi xác nhận Response: {e}")
                self._close_connection(idx)

        elif msg.message_type == MessageType.REGULAR_MESSAGE:
            text = msg.payload.decode('utf-8')
            self.emit("MSG", idx, f"[Peer]: {text}")

    def send_direct(self, idx, text: str):
        state = self.peer_states.get(idx)
        if state and state['handshake_complete']:
            msg = SegMessage.create_regular_message(text)
            final_bytes = msg.to_bytes(tink_aead_primitive=state['aead_primitive'])
            self.emit("LOG", idx, f">>> ĐANG GỬI TIN NHẮN (Tink AEAD)\n" + SegMessage.inspect_packet(final_bytes))
            try:
                self.connections[idx][0].sendall(final_bytes)
                self.emit("MSG", idx, f"[Me]: {text}")
            except:
                self._close_connection(idx)
        else:
            self.emit("LOG", idx, "Chưa hoàn tất Tink Handshake.")

    def _close_connection(self, idx):
        if 0 <= idx < len(self.connections):
            conn = self.connections[idx][0]
            if conn:
                try: conn.close()
                except: pass
            self.connections[idx] = (None, None, None)
            if idx in self.peer_states: del self.peer_states[idx]
            self.emit("DISCONN", idx, "Đã ngắt kết nối")
    
    def close_all(self):
        self.running = False
        if self.listen_sock: self.listen_sock.close()
        for i in range(len(self.connections)):
            self._close_connection(i)