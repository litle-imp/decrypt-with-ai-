import tkinter as tk
from tkinter import ttk, scrolledtext
import base64
import codecs

# Decryption functions
def decrypt_base64(message):
    try:
        return base64.b64decode(message).decode()
    except:
        return "Invalid Base64"

def decrypt_rot13(message):
    return codecs.decode(message, 'rot_13')

def decrypt_caesar(message, shift):
    result = ''
    for char in message:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

def decrypt_hex(message):
    try:
        return bytes.fromhex(message).decode()
    except:
        return "Invalid Hex"

def decrypt_xor(message, key=42):
    try:
        return ''.join(chr(ord(char) ^ key) for char in message)
    except:
        return "Invalid XOR"

def decrypt_binary(message):
    try:
        chars = [chr(int(b, 2)) for b in message.split()]
        return ''.join(chars)
    except:
        return "Invalid Binary"

def decrypt_reverse(message):
    return message[::-1]

# GUI functions
def decrypt_all():
    text = input_text.get("1.0", tk.END).strip()
    output_text.delete("1.0", tk.END)
    
    if not text:
        output_text.insert(tk.END, "Please enter a message.")
        return

    output_text.insert(tk.END, "🔓 Base64:\n" + decrypt_base64(text) + "\n\n")
    output_text.insert(tk.END, "🔓 ROT13:\n" + decrypt_rot13(text) + "\n\n")
    output_text.insert(tk.END, "🔓 Caesar Ciphers:\n")
    for i in range(1, 26):
        output_text.insert(tk.END, f"Shift {i}: {decrypt_caesar(text, i)}\n")
    output_text.insert(tk.END, "\n🔓 Hex:\n" + decrypt_hex(text) + "\n\n")
    output_text.insert(tk.END, "🔓 XOR (key=42):\n" + decrypt_xor(text) + "\n\n")
    output_text.insert(tk.END, "🔓 Binary:\n" + decrypt_binary(text) + "\n\n")
    output_text.insert(tk.END, "🔓 Reversed:\n" + decrypt_reverse(text))

# GUI Layout
root = tk.Tk()
root.title("🛡️ Cipher Identifier & Decryptor")
root.geometry("800x600")

frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)

label = ttk.Label(frame, text="Enter Encrypted Text:")
label.pack(anchor=tk.W)

input_text = scrolledtext.ScrolledText(frame, height=5)
input_text.pack(fill=tk.X)

decrypt_button = ttk.Button(frame, text="🔍 Decrypt All", command=decrypt_all)
decrypt_button.pack(pady=10)

output_label = ttk.Label(frame, text="Decryption Results:")
output_label.pack(anchor=tk.W)

output_text = scrolledtext.ScrolledText(frame, height=20)
output_text.pack(fill=tk.BOTH, expand=True)

root.mainloop()
