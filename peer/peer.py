import socket
import threading
import os
import glob

# --- CRYPTOGRAPHY IMPORTS ---
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

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
        
        # --- PKI LOADING ---
        self.pki_dir = "pki"
        self.key_dir = "key_storage"
        self.ca_cert = self._load_ca_cert()
        self.my_cert, self.my_static_priv_key = self._load_my_identity()

    def _load_ca_cert(self):
        """Load Root CA Certificate để xác thực người khác"""
        try:
            with open(f"{self.pki_dir}/secmsg_root_ca.crt", "rb") as f:
                return x509.load_pem_x509_certificate(f.read())
        except Exception as e:
            print(f"CRITICAL: Cannot load CA Cert: {e}")
            return None

    def _load_my_identity(self):
        """Tự động tìm file key/crt dựa trên Port đang chạy"""
        # Tìm file có dạng *_port{port}.key trong folder pki
        try:
            key_files = glob.glob(f"{self.pki_dir}/*_port{self.port}.key")
            if not key_files:
                print(f"WARNING: No identity found for port {self.port}. Running anonymously.")
                return None, None
            
            key_path = key_files[0]
            crt_path = key_path.replace(".key", ".crt")
            
            with open(key_path, "rb") as f:
                priv_key = serialization.load_pem_private_key(f.read(), password=None)
                
            with open(crt_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                
            print(f"Loaded Identity: {crt_path}")
            return cert, priv_key
        except Exception as e:
            print(f"Error loading identity: {e}")
            return None, None

    def emit(self, event_type, idx, content):
        if self.on_event: self.on_event(event_type, idx, content)

    def _format_hex(self, label, data):
        if not data: return f"{label}: [Empty]"
        return f"{label}: {data.hex()}"

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
                self._add_connection(conn, addr, "in")
            except: break

    def _add_connection(self, conn, addr, direction):
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        idx = len(self.connections)
        self.connections.append((conn, addr, direction))
        
        # 1. Sinh khóa ECDH ngẫu nhiên (Ephemeral Key) - Dùng cho phiên này thôi
        my_ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
        my_ephemeral_pub_bytes = my_ephemeral_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.peer_states[idx] = {
            'addr': addr,
            'my_ephemeral_priv': my_ephemeral_priv,
            'my_ephemeral_pub_bytes': my_ephemeral_pub_bytes,
            'aes_key': None,
            'handshake_complete': False
        }
        
        self.emit("NEW_CONN", idx, f"{addr[0]}:{addr[1]} ({direction})")
        threading.Thread(target=self._recv_loop, args=(idx,), daemon=True).start()
        return idx

    def connect(self, host, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                idx = self._add_connection(sock, (host, port), "out")
                
                # Gửi REQUEST (Mặc định)
                self._send_handshake(idx, msg_type=MessageType.HANDSHAKE_REQUEST) 
                
            except Exception as e:
                print(f"Error connecting: {e}")

    # Sửa dòng định nghĩa hàm: thêm tham số msg_type
    def _send_handshake(self, idx, msg_type=MessageType.HANDSHAKE_REQUEST):
        """
        Đóng gói Handshake Payload:
        [Cert Len (2)][Certificate (DER)][Sig Len (2)][Signature][Ephemeral Pub Key]
        """
        state = self.peer_states[idx]
        
        # 1. Lấy Certificate bytes (DER format)
        cert_bytes = self.my_cert.public_bytes(serialization.Encoding.DER)
        
        # 2. Tạo Chữ ký (Signature) cho Ephemeral Key
        signature = self.my_static_priv_key.sign(
            state['my_ephemeral_pub_bytes'],
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        # 3. Đóng gói Payload
        payload = (
            len(cert_bytes).to_bytes(2, 'big') + cert_bytes +
            len(signature).to_bytes(2, 'big') + signature +
            state['my_ephemeral_pub_bytes']
        )
        
        # --- SỬA ĐOẠN NÀY: Chọn loại Message dựa trên tham số ---
        if msg_type == MessageType.HANDSHAKE_REQUEST:
            req = SegMessage.create_handshake_request(payload)
            log_prefix = "REQUEST"
        else:
            req = SegMessage.create_handshake_response(payload)
            log_prefix = "RESPONSE"
        # -------------------------------------------------------
        
        # Log Inspection
        log_info = (f">>> SENDING AUTHENTICATED HANDSHAKE ({log_prefix})\n"
                    f"Certificate: {self.my_cert.subject}\n"
                    f"Signature Len: {len(signature)}\n"
                    f"Ephemeral Key Len: {len(state['my_ephemeral_pub_bytes'])}")
        self.emit("LOG", idx, log_info)
        
        self.connections[idx][0].sendall(req.to_bytes())

    def _recv_loop(self, idx):
        conn = self.connections[idx][0]
        buffer = b""  
        

        HEADER_SIZE = 31 

        while True:
            try:
                data = conn.recv(8192)
                if not data: break
                

                buffer += data

                while True:

                    if len(buffer) < HEADER_SIZE:
                        break
                    
                    payload_len = int.from_bytes(buffer[19:23], 'big')
                    

                    total_packet_len = HEADER_SIZE + payload_len

                    if len(buffer) < total_packet_len:

                        break
                    

                    packet = buffer[:total_packet_len] 
                    buffer = buffer[total_packet_len:] 
                    
                    self.handle_data(idx, packet)
                    
            except Exception as e:
                self.emit("LOG", idx, f"Error recv loop: {e}")
                break
        
        self._close_connection(idx)

    def handle_data(self, idx, data: bytes):
        state = self.peer_states[idx]
        aes_k = state.get('aes_key')

        self.emit("LOG", idx, f"<<< RECEIVED PACKET ({len(data)} bytes)")

        try:
            msg = SegMessage.from_bytes(data, aes_key=aes_k)
        except ValueError as e:
            if not state['handshake_complete']:
                try: msg = SegMessage.from_bytes(data, aes_key=None)
                except: return
            else:
                self.emit("LOG", idx, f"Integrity Failed: {e}")
                return

        if msg.message_type in [MessageType.HANDSHAKE_REQUEST, MessageType.HANDSHAKE_RESPONSE]:
            try:
                payload = msg.payload
                cursor = 0
                
                # 1. Parse Certificate
                cert_len = int.from_bytes(payload[cursor:cursor+2], 'big'); cursor += 2
                cert_bytes = payload[cursor:cursor+cert_len]; cursor += cert_len
                peer_cert = x509.load_der_x509_certificate(cert_bytes)
                
                # 2. Parse Signature
                sig_len = int.from_bytes(payload[cursor:cursor+2], 'big'); cursor += 2
                signature = payload[cursor:cursor+sig_len]; cursor += sig_len
                
                # 3. Parse Ephemeral Public Key
                peer_ephemeral_bytes = payload[cursor:]
                
                # --- VERIFICATION STEP ---
                
                # A. Verify Certificate chain (Kiểm tra xem Cert này có phải do CA cấp không)
                # Note: PyCA verify hơi phức tạp, ở đây ta verify chữ ký trên Cert bằng CA Public Key
                self.ca_cert.public_key().verify(
                    peer_cert.signature,
                    peer_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    peer_cert.signature_hash_algorithm
                )
                self.emit("LOG", idx, "✔ Certificate Verified (Trusted by Root CA)")
                
                # B. Verify Signature (Kiểm tra xem Peer có sở hữu Private Key của Cert không)
                # Dùng Public Key trong Cert để verify Signature của Ephemeral Key
                peer_cert.public_key().verify(
                    signature,
                    peer_ephemeral_bytes,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                self.emit("LOG", idx, f"✔ Signature Verified (Identity: {peer_cert.subject})")
                
                # --- ECDH EXCHANGE ---
                peer_ephemeral_pub = serialization.load_der_public_key(peer_ephemeral_bytes)
                shared_secret = state['my_ephemeral_priv'].exchange(ec.ECDH(), peer_ephemeral_pub)
                
                derived_key = HKDF(
                    algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data'
                ).derive(shared_secret)
                
                state['aes_key'] = derived_key
                state['handshake_complete'] = True
                
                log_msg = (f"*** SECURE AUTHENTICATED CHANNEL ESTABLISHED ***\n"
                           f"Peer Identity: {peer_cert.subject}\n"
                           f"{self._format_hex('AES Key', derived_key)}")
                self.emit("LOG", idx, log_msg)

                # Nếu là Request thì gửi lại Response của mình
                if msg.message_type == MessageType.HANDSHAKE_REQUEST:
                    self._send_handshake(idx, msg_type=MessageType.HANDSHAKE_RESPONSE)

            except Exception as e:
                self.emit("LOG", idx, f"❌ HANDSHAKE FAILED: {e}")
                self._close_connection(idx)

        elif msg.message_type == MessageType.REGULAR_MESSAGE:
            text = msg.payload.decode('utf-8')
            self.emit("MSG", idx, f"[Peer]: {text}")

    def send_direct(self, idx, text: str):
        state = self.peer_states.get(idx)
        if state and state['handshake_complete']:
            msg = SegMessage.create_regular_message(text)
            final_bytes = msg.to_bytes(aes_key=state['aes_key'])
            self.emit("LOG", idx, f">>> SENDING MSG\n" + SegMessage.inspect_packet(final_bytes))
            try:
                self.connections[idx][0].sendall(final_bytes)
                self.emit("MSG", idx, f"[Me]: {text}")
            except:
                self._close_connection(idx)
        else:
            self.emit("LOG", idx, "Handshake not complete.")

    def _close_connection(self, idx):
        if 0 <= idx < len(self.connections):
            conn = self.connections[idx][0]
            if conn:
                try: conn.close()
                except: pass
            self.connections[idx] = (None, None, None)
            if idx in self.peer_states: del self.peer_states[idx]
            self.emit("DISCONN", idx, "Disconnected")
    
    def close_all(self):
        self.running = False
        if self.listen_sock: self.listen_sock.close()
        for i in range(len(self.connections)):
            self._close_connection(i)