
import gradio as gr
import rsa
import base64

# ========================================================
# SINH KHÓA RSA
# ========================================================

def generate_keys(bit_size):
    public_key, private_key = rsa.newkeys(bit_size)

    return (
        private_key.save_pkcs1().decode(),
        public_key.save_pkcs1().decode()
    )

# ========================================================
# MÃ HÓA
# ========================================================

def encrypt_message(message, public_key_text):
    try:
        public_key = rsa.PublicKey.load_pkcs1(
            public_key_text.encode()
        )

        encrypted = rsa.encrypt(
            message.encode("utf-8"),
            public_key
        )

        return base64.b64encode(encrypted).decode()

    except Exception as e:
        return f"Lỗi mã hóa: {e}"

# ========================================================
# GIẢI MÃ
# ========================================================

def decrypt_message(cipher_base64, private_key_text):
    try:
        private_key = rsa.PrivateKey.load_pkcs1(
            private_key_text.encode()
        )

        encrypted_data = base64.b64decode(cipher_base64)

        decrypted = rsa.decrypt(
            encrypted_data,
            private_key
        )

        return decrypted.decode("utf-8")

    except Exception as e:
        return f"Lỗi giải mã: {e}"

# ========================================================
# GIAO DIỆN
# ========================================================

with gr.Blocks(title="RSA Encryption Demo - Ông Đinh Hoàng Gia") as demo:

    gr.Markdown("""
# 🔐 RSA Encryption Demo - Ông Đinh Hoàng Gia

## Chức năng
- Sinh cặp khóa RSA
- Mã hóa UTF8 tiếng Việt
- Xuất Base64
- Giải mã thông báo
""")

    # ========================================================
    # TAB SINH KHÓA
    # ========================================================

    with gr.Tab("1. Sinh khóa RSA"):

        bit_size = gr.Dropdown(
            choices=[1024, 2048, 3072, 4096],
            value=2048,
            label="Kích thước khóa RSA"
        )

        btn_gen = gr.Button("Sinh khóa RSA")

        private_key_box = gr.Textbox(
            label="Private Key (BÍ MẬT)",
            lines=12
        )

        public_key_box = gr.Textbox(
            label="Public Key (GỬI CÔNG KHAI)",
            lines=12
        )

        btn_gen.click(
            generate_keys,
            inputs=bit_size,
            outputs=[private_key_box, public_key_box]
        )

    # ========================================================
    # TAB MÃ HÓA
    # ========================================================

    with gr.Tab("2. Mã hóa thông báo"):

        plaintext_box = gr.Textbox(
            label="Thông báo UTF8 tiếng Việt",
            lines=5,
placeholder="Ví dụ: Xin chào ông Đinh Hoàng Gia!"
        )

        public_encrypt_box = gr.Textbox(
            label="Public Key của ông Gia",
            lines=10
        )

        encrypt_btn = gr.Button("Mã hóa")

        cipher_box = gr.Textbox(
            label="Ciphertext Base64",
            lines=8
        )

        encrypt_btn.click(
            encrypt_message,
            inputs=[plaintext_box, public_encrypt_box],
            outputs=cipher_box
        )

    # ========================================================
    # TAB GIẢI MÃ
    # ========================================================

    with gr.Tab("3. Giải mã thông báo"):

        cipher_input_box = gr.Textbox(
            label="Ciphertext Base64",
            lines=8
        )

        private_decrypt_box = gr.Textbox(
            label="Private Key bí mật",
            lines=10
        )

        decrypt_btn = gr.Button("Giải mã")

        decrypted_box = gr.Textbox(
            label="Thông báo gốc",
            lines=5
        )

        decrypt_btn.click(
            decrypt_message,
            inputs=[cipher_input_box, private_decrypt_box],
            outputs=decrypted_box
        )

    # ========================================================
    # LƯU Ý BẢO MẬT
    # ========================================================

    with gr.Accordion("Lưu ý bảo mật", open=False):

        gr.Markdown("""
## ⚠️ Lưu ý

### Private Key
- Phải giữ bí mật tuyệt đối
- Không gửi cho người khác

### Public Key
- Có thể gửi công khai
- Dùng để mã hóa dữ liệu gửi cho ông Gia

### RSA không phù hợp cho dữ liệu lớn
- RSA thường chỉ mã hóa khóa AES
- Dữ liệu lớn nên dùng Hybrid Encryption
""")

# ========================================================
# CHẠY ỨNG DỤNG
# ========================================================

if __name__ == "__main__":
    demo.launch()
