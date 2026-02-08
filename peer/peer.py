import socket
import threading
import hashlib
from protocol.v0_1 import SegMessage, MessageType
from Diffie_Hellman import DH
from HMAC.hmac_key_generation import derive_key_from_aes_key

class Peer:
    def __init__(self, host='0.0.0.0', port=5000, on_event=None):
        self.host = host
        self.port = port
        self.listen_sock = None
        self.running = False
        self.connections = [] 
        self.peer_states = {} 
        self.on_event = on_event

    def emit(self, event_type, idx, content):
        if self.on_event:
            self.on_event(event_type, idx, content)

    def _format_hex(self, label, data):
        if isinstance(data, int):
            data = data.to_bytes((data.bit_length() + 7) // 8, 'big')
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
        
        my_priv = DH.generate_private_key()
        my_pub_int = DH.calculate_public_key(my_priv)
        my_pub = my_pub_int.to_bytes(256, 'big')

        self.peer_states[idx] = {
            'addr': addr,
            'my_private_key': my_priv,
            'my_public_key': my_pub,
            'peer_public_key': None,
            'shared_secret': None,
            'aes_key': None,
            'hmac_key': None,
            'handshake_complete': False
        }
        
        self.emit("NEW_CONN", idx, f"{addr[0]}:{addr[1]} ({direction})")
        
        # Log Key khởi tạo
        log_msg = (f"--- INIT KEYS ---\n"
                   f"My Private Key: [HIDDEN] (Security)\n"
                   f"{self._format_hex('My Public Key', my_pub)}")
        self.emit("LOG", idx, log_msg)
        
        threading.Thread(target=self._recv_loop, args=(idx,), daemon=True).start()
        return idx

    def connect(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            idx = self._add_connection(sock, (host, port), "out")
            
            state = self.peer_states[idx]
            req = SegMessage.create_handshake_request(state['my_public_key'])
            
            # --- LOG PACKET GỬI ĐI ---
            raw_bytes = req.to_bytes()
            self.emit("LOG", idx, f">>> SENDING HANDSHAKE\n" + SegMessage.inspect_packet(raw_bytes))
            
            sock.sendall(raw_bytes) 
        except Exception as e:
            print(f"Error connecting: {e}")

    def _recv_loop(self, idx):
        conn = self.connections[idx][0]
        while True:
            try:
                data = conn.recv(8192)
                if not data: break
                self.handle_data(idx, data)
            except Exception as e:
                self.emit("LOG", idx, f"Error recv: {e}")
                break
        self._close_connection(idx)

    def handle_data(self, idx, data: bytes):
        state = self.peer_states[idx]
        aes_k = state.get('aes_key')
        hmac_k = state.get('hmac_key')

        # --- LOG PACKET NHẬN ĐƯỢC ---
        # Gọi hàm inspect_packet để soi chi tiết header
        self.emit("LOG", idx, f"<<< RECEIVED PACKET\n" + SegMessage.inspect_packet(data))

        try:
            msg = SegMessage.from_bytes(data, aes_key=aes_k, hmac_key=hmac_k)
        except ValueError as e:
            if not state['handshake_complete']:
                try:
                    msg = SegMessage.from_bytes(data, aes_key=None, hmac_key=None)
                except:
                    return
            else:
                self.emit("LOG", idx, f"integrity Check Failed: {e}")
                return

        # Handshake Logic
        if msg.message_type == MessageType.HANDSHAKE_REQUEST:
            peer_pk = int.from_bytes(msg.payload, 'big')
            state['peer_public_key'] = peer_pk
            shared_secret_int = DH.calculate_shared_secret(peer_pk, state['my_private_key'])
            shared_secret_bytes = shared_secret_int.to_bytes(256, 'big')
            
            master_key = hashlib.sha256(shared_secret_bytes).digest()
            state['aes_key'] = master_key
            state['hmac_key'] = derive_key_from_aes_key(master_key, b"HMAC", 32)
            state['handshake_complete'] = True
            
            log_msg = (f"*** KEYS ESTABLISHED ***\n"
                       f"{self._format_hex('Shared Secret', shared_secret_bytes)}\n"
                       f"{self._format_hex('AES Key', state['aes_key'])}\n"
                       f"{self._format_hex('HMAC Key', state['hmac_key'])}")
            self.emit("LOG", idx, log_msg)

            resp = SegMessage.create_handshake_response(state['my_public_key'])
            
            # Log Response Packet
            raw_resp = resp.to_bytes()
            self.emit("LOG", idx, f">>> SENDING HANDSHAKE RESPONSE\n" + SegMessage.inspect_packet(raw_resp))
            
            self.connections[idx][0].sendall(raw_resp)

        elif msg.message_type == MessageType.HANDSHAKE_RESPONSE:
            peer_pk = int.from_bytes(msg.payload, 'big')
            state['peer_public_key'] = peer_pk
            shared_secret_int = DH.calculate_shared_secret(peer_pk, state['my_private_key'])
            shared_secret_bytes = shared_secret_int.to_bytes(256, 'big')
            
            master_key = hashlib.sha256(shared_secret_bytes).digest()
            state['aes_key'] = master_key
            state['hmac_key'] = derive_key_from_aes_key(master_key, b"HMAC", 32)
            state['handshake_complete'] = True
            
            log_msg = (f"*** KEYS ESTABLISHED ***\n"
                       f"{self._format_hex('Shared Secret', shared_secret_bytes)}\n"
                       f"{self._format_hex('AES Key', state['aes_key'])}\n"
                       f"{self._format_hex('HMAC Key', state['hmac_key'])}")
            self.emit("LOG", idx, log_msg)

        elif msg.message_type == MessageType.REGULAR_MESSAGE:
            text = msg.payload.decode('utf-8')
            self.emit("MSG", idx, f"[Peer]: {text}")

    def send_direct(self, idx, text: str):
        state = self.peer_states.get(idx)
        if state and state['handshake_complete']:
            msg = SegMessage.create_regular_message(text)
            
            # Lấy bytes cuối cùng (đã mã hóa + HMAC)
            final_bytes = msg.to_bytes(aes_key=state['aes_key'], hmac_key=state['hmac_key'])
            
            # Log chi tiết gói tin sắp gửi
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