import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, ttk
from peer.peer import Peer

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure P2P Protocol Inspector") 
        self.root.geometry("1000x700") 

        # --- Data ---
        self.peer = None
        self.sessions = {} 
        self.current_idx = None 

        # --- Style Configuration ---
        style = ttk.Style()
        style.theme_use('clam')
        
        # --- Top Bar ---
        self.frame_top = tk.Frame(root, bg="#2c3e50", pady=10)
        self.frame_top.pack(fill=tk.X)

        tk.Label(self.frame_top, text=" LOCAL PORT: ", bg="#2c3e50", fg="white", font=("Consolas", 10, "bold")).pack(side=tk.LEFT)
        self.entry_port = tk.Entry(self.frame_top, width=6, font=("Consolas", 10))
        self.entry_port.insert(0, "5000")
        self.entry_port.pack(side=tk.LEFT)

        self.btn_listen = tk.Button(self.frame_top, text="START LISTENING", command=self.start_server, 
                                    bg="#27ae60", fg="white", font=("Consolas", 9, "bold"), relief="flat")
        self.btn_listen.pack(side=tk.LEFT, padx=10)

        self.btn_connect = tk.Button(self.frame_top, text="CONNECT TO PEER", command=self.open_connect_dialog, 
                                     bg="#2980b9", fg="white", font=("Consolas", 9, "bold"), relief="flat")
        self.btn_connect.pack(side=tk.RIGHT, padx=10)

        # --- Main Layout ---
        self.main_pane = tk.PanedWindow(root, orient=tk.HORIZONTAL, sashwidth=4, bg="#ecf0f1")
        self.main_pane.pack(fill=tk.BOTH, expand=True)

        # Sidebar
        self.sidebar_frame = tk.Frame(self.main_pane, bg="#34495e")
        tk.Label(self.sidebar_frame, text="CONNECTIONS", bg="#34495e", fg="#ecf0f1", font=("Arial", 10, "bold"), pady=5).pack(fill=tk.X)
        
        self.listbox_peers = tk.Listbox(self.sidebar_frame, font=("Arial", 11), selectmode=tk.SINGLE, 
                                        bg="#ecf0f1", bd=0, highlightthickness=0)
        self.listbox_peers.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.listbox_peers.bind('<<ListboxSelect>>', self.on_peer_select)
        
        self.main_pane.add(self.sidebar_frame, minsize=200)

        # Right Container
        self.right_frame_container = tk.Frame(self.main_pane, bg="#bdc3c7")
        self.main_pane.add(self.right_frame_container, minsize=600)

        self.lbl_intro = tk.Label(self.right_frame_container, text="Protocol Inspector Ready.\nWaiting for connections...", 
                                  fg="#7f8c8d", bg="#bdc3c7", font=("Segoe UI", 16))
        self.lbl_intro.place(relx=0.5, rely=0.5, anchor="center")

    def start_server(self):
        try:
            port = int(self.entry_port.get())
            self.peer = Peer(port=port, on_event=self.handle_peer_event_threadsafe)
            self.peer.start_listening()
            self.btn_listen.config(state='disabled', text="LISTENING...")
            self.entry_port.config(state='disabled')
        except ValueError:
            messagebox.showerror("Error", "Invalid Port")

    def open_connect_dialog(self):
        if not self.peer:
            messagebox.showwarning("Warning", "Start server first!")
            return
        target = simpledialog.askstring("Connect", "Target (host:port)")
        if target:
            try:
                host, p = target.split(":")
                self.peer.connect(host, int(p))
            except:
                messagebox.showerror("Error", "Invalid format")

    def handle_peer_event_threadsafe(self, event_type, idx, content):
        self.root.after(0, lambda: self.process_peer_event(event_type, idx, content))

    def process_peer_event(self, event_type, idx, content):
        if event_type == "NEW_CONN":
            self.create_session_ui(idx, content)
            return
        if event_type == "DISCONN":
            self.append_log(idx, "\n[!] DISCONNECTED", "error")
            return
        if event_type == "LOG":
            self.append_log(idx, content, "info")
        elif event_type == "MSG":
            self.append_chat(idx, content)

    def create_session_ui(self, idx, title):
        self.listbox_peers.insert(tk.END, f" #{idx} {title}")
        
        session_frame = tk.Frame(self.right_frame_container, bg="#bdc3c7")
        
        # Split: Top (Chat) / Bottom (Inspector Log)
        pane = tk.PanedWindow(session_frame, orient=tk.VERTICAL, sashwidth=4, bg="#bdc3c7")
        pane.pack(fill=tk.BOTH, expand=True)

        # --- Chat UI ---
        chat_frame = tk.Frame(pane, bg="white")
        tk.Label(chat_frame, text=" HUMAN READABLE CHAT ", bg="#3498db", fg="white", font=("Arial", 8, "bold"), anchor="w").pack(fill=tk.X)
        
        txt_chat = scrolledtext.ScrolledText(chat_frame, state='disabled', height=8, font=("Segoe UI", 11))
        txt_chat.pack(fill=tk.BOTH, expand=True)
        
        input_frame = tk.Frame(chat_frame, bg="#ecf0f1", pady=5)
        input_frame.pack(fill=tk.X)
        entry_msg = tk.Entry(input_frame, font=("Segoe UI", 11))
        entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        btn_send = tk.Button(input_frame, text="SEND", command=lambda: self.send_message(idx, entry_msg), 
                             bg="#3498db", fg="white", font=("Arial", 9, "bold"), relief="flat")
        btn_send.pack(side=tk.LEFT, padx=5)
        entry_msg.bind("<Return>", lambda e: self.send_message(idx, entry_msg))

        pane.add(chat_frame, minsize=150)

        # --- Inspector Log UI ---
        log_frame = tk.Frame(pane, bg="#2c3e50") # Dark background
        tk.Label(log_frame, text=" PROTOCOL INSPECTOR (AES-CTR / HMAC-SHA256 / Diffie-Hellman) ", 
                 bg="#e67e22", fg="white", font=("Consolas", 9, "bold"), anchor="w").pack(fill=tk.X)
        
        # Text widget nền đen, chữ xanh lá giống Matrix/Hacker
        txt_log = scrolledtext.ScrolledText(log_frame, state='disabled', height=15, 
                                            font=("Consolas", 10), bg="#1e1e1e", fg="#00ff00", insertbackground="white")
        txt_log.pack(fill=tk.BOTH, expand=True)
        
        # Định nghĩa tag màu cho log đẹp hơn
        txt_log.tag_config("info", foreground="#00ff00") # Green
        txt_log.tag_config("error", foreground="#ff5555") # Red
        txt_log.tag_config("header", foreground="#f1c40f", font=("Consolas", 10, "bold")) # Yellow

        pane.add(log_frame, minsize=200)

        self.sessions[idx] = {
            'frame': session_frame,
            'chat': txt_chat,
            'log': txt_log,
            'entry': entry_msg
        }

        if self.current_idx is None:
            self.listbox_peers.selection_set(0)
            self.switch_to_peer(idx)

    def on_peer_select(self, event):
        selection = self.listbox_peers.curselection()
        if selection:
            self.switch_to_peer(selection[0])

    def switch_to_peer(self, idx):
        if idx not in self.sessions: return
        self.lbl_intro.place_forget()
        if self.current_idx is not None and self.current_idx in self.sessions:
            self.sessions[self.current_idx]['frame'].pack_forget()

        self.current_idx = idx
        self.sessions[idx]['frame'].pack(fill=tk.BOTH, expand=True)
        self.sessions[idx]['entry'].focus()

    def send_message(self, idx, entry):
        text = entry.get()
        if text:
            self.peer.send_direct(idx, text)
            entry.delete(0, tk.END)

    def append_chat(self, idx, text):
        if idx in self.sessions:
            w = self.sessions[idx]['chat']
            w.config(state='normal')
            w.insert(tk.END, text + "\n")
            w.see(tk.END)
            w.config(state='disabled')

    def append_log(self, idx, text, tag="info"):
        if idx in self.sessions:
            w = self.sessions[idx]['log']
            w.config(state='normal')
            
            # Thêm dòng phân cách nếu là Log block mới
            if "---" in text or ">>>" in text or "<<<" in text:
                w.insert(tk.END, "\n" + "="*60 + "\n", "header")
            
            w.insert(tk.END, text + "\n", tag)
            w.see(tk.END)
            w.config(state='disabled')

    def on_closing(self):
        if self.peer: self.peer.close_all()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()