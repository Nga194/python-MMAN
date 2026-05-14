# ==========================================
# IMPORT
# ==========================================
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import MD5
import base64
import gradio as gr
import os

# ==========================================
# HÀM XỬ LÝ KHÓA DES (FIX QUAN TRỌNG)
# Dùng MD5 để tránh lỗi Unicode
# ==========================================
def format_key(key_text):
    return MD5.new(key_text.encode("utf-8")).digest()[:8]

# ==========================================
# MÃ HÓA TEXT
# ==========================================
def encrypt_text(plain_text, key_text):
    try:
        if not plain_text:
            return "Vui lòng nhập văn bản"

        key = format_key(key_text)

        cipher = DES.new(key, DES.MODE_CBC)

        padded_text = pad(plain_text.encode("utf-8"), DES.block_size)

        encrypted_bytes = cipher.encrypt(padded_text)

        result = base64.b64encode(cipher.iv + encrypted_bytes).decode("utf-8")

        return result

    except Exception as e:
        return f"Lỗi: {str(e)}"


# ==========================================
# GIẢI MÃ TEXT (FIX UTF-8 + LỖI KEY)
# ==========================================
def decrypt_text(cipher_text, key_text):
    try:
        if not cipher_text:
            return "Vui lòng nhập dữ liệu mã hóa"

        key = format_key(key_text)

        data = base64.b64decode(cipher_text)

        if len(data) < 8:
            return "Lỗi: dữ liệu không hợp lệ"

        iv = data[:8]
        encrypted_data = data[8:]

        cipher = DES.new(key, DES.MODE_CBC, iv)

        decrypted = unpad(
            cipher.decrypt(encrypted_data),
            DES.block_size
        )

        return decrypted.decode("utf-8")

    except ValueError:
        return "Lỗi: Sai key hoặc dữ liệu bị hỏng"
    except Exception as e:
        return f"Lỗi: {str(e)}"


# ==========================================
# MÃ HÓA FILE
# ==========================================
def encrypt_file(file_obj, key_text):
    try:
        if file_obj is None:
            return None

        key = format_key(key_text)

        input_path = file_obj.name

        with open(input_path, "rb") as f:
            file_data = f.read()

        cipher = DES.new(key, DES.MODE_CBC)

        encrypted_data = cipher.encrypt(
            pad(file_data, DES.block_size)
        )

        output_path = "encrypted.des"

        with open(output_path, "wb") as f:
            f.write(cipher.iv + encrypted_data)

        return output_path

    except Exception as e:
        return f"Lỗi: {str(e)}"


# ==========================================
# GIẢI MÃ FILE
# ==========================================
def decrypt_file(file_obj, key_text):
    try:
        if file_obj is None:
            return None

        key = format_key(key_text)

        input_path = file_obj.name

        with open(input_path, "rb") as f:
            file_data = f.read()

        if len(file_data) < 8:
            return "File không hợp lệ"

        iv = file_data[:8]
        encrypted_data = file_data[8:]

        cipher = DES.new(key, DES.MODE_CBC, iv)

        decrypted_data = unpad(
            cipher.decrypt(encrypted_data),
            DES.block_size
        )

        output_path = "decrypted_output"

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        return output_path

    except ValueError:
        return "Sai key hoặc file bị lỗi"
    except Exception as e:
        return f"Lỗi: {str(e)}"


# ==========================================
# GIAO DIỆN GRADIO
# ==========================================
with gr.Blocks(title="DES Encryption App") as demo:

    gr.Markdown("# 🔐 DES Encryption & Decryption (Unicode OK)")

    # =========================
    # TAB TEXT
    # =========================
    with gr.Tab("Text Encryption"):

        txt_input = gr.Textbox(
            label="Nhập văn bản (hỗ trợ tiếng Việt)",
            lines=5
        )

        txt_key = gr.Textbox(
            label="Khóa",
            type="password"
        )

        with gr.Row():
            btn_encrypt_text = gr.Button("Mã hóa")
            btn_decrypt_text = gr.Button("Giải mã")

        txt_output = gr.Textbox(
            label="Kết quả",
            lines=5
        )

        btn_encrypt_text.click(
            encrypt_text,
            inputs=[txt_input, txt_key],
            outputs=txt_output
        )

        btn_decrypt_text.click(
            decrypt_text,
            inputs=[txt_input, txt_key],
            outputs=txt_output
        )

    # =========================
    # TAB FILE
    # =========================
    with gr.Tab("File Encryption"):

        file_input = gr.File(
            label="Chọn file"
        )

        file_key = gr.Textbox(
            label="Khóa",
            type="password"
        )

        with gr.Row():
            btn_encrypt_file = gr.Button("Mã hóa File")
            btn_decrypt_file = gr.Button("Giải mã File")

        file_output = gr.File(
            label="Tải file kết quả"
        )

        btn_encrypt_file.click(
            encrypt_file,
            inputs=[file_input, file_key],
            outputs=file_output
        )

        btn_decrypt_file.click(
            decrypt_file,
            inputs=[file_input, file_key],
            outputs=file_output
        )

# ==========================================
# CHẠY APP
# ==========================================
demo.launch(share=True)