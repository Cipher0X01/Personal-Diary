import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter.scrolledtext import ScrolledText
import os
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key(password_provided):
    password = password_provided.encode()
    salt = b'\x1a\xa6\x98\xef\x12\xee\x5b\x4a'  
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


password = simpledialog.askstring("Password", "Enter your diary password:", show='*')
if password is None or password == "":
    messagebox.showerror("Error", "No password provided. Exiting application.")
    exit()

key = generate_key(password)
fernet = Fernet(key)


root = tk.Tk()
root.title("Personal Diary")


text_area = ScrolledText(root, wrap=tk.WORD, width=40, height=10, font=("Arial", 12))
text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)


def save_entry():
    entry_text = text_area.get("1.0", tk.END)
    encrypted_text = fernet.encrypt(entry_text.encode())
    file_name = f"entry_{len(os.listdir('.')) + 1}.txt"
    with open(file_name, "wb") as file:
        file.write(encrypted_text)
    text_area.delete("1.0", tk.END)
    messagebox.showinfo("Info", "Entry saved successfully.")


def view_entries():
    for file_name in os.listdir("."):
        if file_name.startswith("entry_") and file_name.endswith(".txt"):
            with open(file_name, "rb") as file:
                encrypted_text = file.read()
            decrypted_text = fernet.decrypt(encrypted_text).decode()
            messagebox.showinfo(file_name, decrypted_text)


save_button = tk.Button(root, text="Save Entry", command=save_entry)
save_button.pack(side=tk.LEFT, padx=10, pady=10)

view_button = tk.Button(root, text="View Entries", command=view_entries)
view_button.pack(side=tk.RIGHT, padx=10, pady=10)


root.mainloop()
