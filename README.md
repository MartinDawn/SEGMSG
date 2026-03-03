## 🛡️ Phân tích Kỹ thuật: OpenSSL vs. Google Tink

Trong quá trình phát triển dự án `SecMsg`, hệ thống đã được nâng cấp từ việc sử dụng các thư viện mật mã truyền thống (OpenSSL/Cryptography) sang **Google Tink**. Dưới đây là bảng so sánh chi tiết về sự khác biệt giữa hai phương pháp tiếp cận.

### 1. So sánh về độ phức tạp (Mã nguồn)

| Đặc điểm | Triển khai OpenSSL (`cryptography`) | Triển khai Google Tink |
| :--- | :--- | :--- |
| **Dòng mã xử lý (LOC)** | ~35 dòng (Phải tự quản lý Nonce, Tag, AAD) | ~2 dòng (Sử dụng Primitives) |
| **Quản lý Nonce/IV** | Thủ công (`os.urandom(12)`) | **Tự động 100%** bên trong Primitive |
| **Định dạng bản mã** | Tự ghép chuỗi byte (`Nonce + Cipher + Tag`) | Định dạng chuẩn **Tink Blob** (KeyID + Cipher) |
| **Quản lý Khóa** | File `.key` / `.crt` thô, khó xoay vòng | Hệ thống **Keyset** (JSON) hỗ trợ xoay vòng khóa |



### 2. Các điểm yếu bảo mật (Vulnerabilities) được loại bỏ

Việc sử dụng Google Tink giúp loại bỏ các lỗi mật mã phổ biến (Cryptographic Failures) mà  thường mắc phải khi dùng OpenSSL thô:

#### 🚫 Lỗi Tái sử dụng Nonce (Nonce Reuse)
* **OpenSSL:** Nếu  vô tình dùng lại cùng một Nonce cho hai tin nhắn khác nhau với cùng một khóa AES-GCM, toàn bộ tính bảo mật của thuật toán sẽ sụp đổ (rò rỉ khóa xác thực).
* **Tink:** Primitive `AEAD` của Tink tự động quản lý việc sinh Nonce ngẫu nhiên và an toàn cho mỗi lần gọi `encrypt()`.  không bao giờ nhìn thấy hoặc phải chạm vào Nonce.

#### 🚫 Lỗi Xác thực dữ liệu liên kết (AAD Mismatch)
* **OpenSSL:** Việc truyền `header_aad` vào hàm `encrypt` và `decrypt` đòi hỏi sự chính xác tuyệt đối về thứ tự byte. Sai lệch 1 byte sẽ dẫn đến lỗi logic khó truy vết.
* **Tink:** Tink ép buộc cấu trúc AAD đi kèm với Primitive, giúp việc kiểm tra tính toàn vẹn của Header (Protocol ID, Timestamp) trở nên nhất quán và an toàn hơn.

#### 🚫 Lỗi Cắt mảnh dữ liệu (Byte Slicing Errors)
* **OpenSSL:** Khi nhận gói tin,  phải nhớ: "12 byte đầu là Nonce, 16 byte cuối là Tag". Chỉ cần tính toán sai vị trí cursor, hàm giải mã sẽ crash hoặc trả về dữ liệu rác.
* **Tink:** Toàn bộ bản mã được đóng gói thành một `Tink Blob`. Hàm `decrypt()` tự động biết cách bóc tách các thành phần bên trong dựa trên tiêu đề gói tin.

### 3. Kết luận: Thay đổi Triết lý

Việc chuyển đổi từ OpenSSL sang Tink đại diện cho sự thay đổi tư duy từ **"Cung cấp công cụ" (Tools)** sang **"Cung cấp giải pháp" (Solutions)**. 
* **OpenSSL** cung cấp các linh kiện cơ khí (thuật toán thô), đòi hỏi người thợ phải rất lành nghề để không lắp sai. 
