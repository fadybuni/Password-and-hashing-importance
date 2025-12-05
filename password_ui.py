# simple password UI

import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox

import pyperclip  # make sure to install: pip install pyperclip

from password_security_tool import (
    check_password_strength,
    sha1_hash,
    bcrypt_hash,
    export_sha1_hash,
    export_bcrypt_hash,
    run_john_show,
    simulate_bcrypt_attempt,
)

# window setup
root = tk.Tk()
root.title("Password Security Demo")
root.geometry("720x680")


# copy command helper
def copy_command():
    cmd = "john --format=Raw-SHA1 --wordlist=wordlist_demo.txt sha1_for_cracking.txt"
    pyperclip.copy(cmd)
    messagebox.showinfo("Copied", "Terminal command copied!")


# process user password
def process_password():
    pwd = entry.get()
    score, fb = check_password_strength(pwd)

    sha1_val = sha1_hash(pwd)
    bcrypt_val = bcrypt_hash(pwd)

    export_sha1_hash(sha1_val)
    export_bcrypt_hash(bcrypt_val)

    output = ""

    # score message
    if score < 3:
        output += "⚠️ Weak password — still hashed for demo.\n\n"
    else:
        output += "✔ Strong password.\n\n"

    # show hashes
    output += f"🔐 bcrypt hash (strong):\n{bcrypt_val}\n\n"
    output += f"⚠️ SHA-1 hash (weak):\n{sha1_val}\n\n"

    # show cracking command
    output += "📌 Terminal command to crack SHA-1:\n"
    output += "john --format=Raw-SHA1 --wordlist=wordlist_demo.txt sha1_for_cracking.txt\n\n"

    # save notice
    output += "💾 Hash saved to sha1_for_cracking.txt\n\n"

    # suggestions
    if fb:
        output += "Suggestions:\n"
        for item in fb:
            output += f"- {item}\n"

    text_box.delete("1.0", tk.END)
    text_box.insert(tk.END, output)


# show john results
def show_john_results():
    raw = run_john_show()

    cracked_password = None

    for line in raw.splitlines():
        if ":" in line and "password hashes cracked" not in line:
            cracked_password = line.split(":")[1].strip()

    output = "=== SHA-1 Crack Results ===\n\n"

    if cracked_password:
        output += f"✔ SUCCESS — Password cracked!\n"
        output += f"🔓 Password: {cracked_password}\n\n"
    else:
        output += "❌ No passwords cracked.\n\n"

    output += "💨 SHA-1 cracks extremely fast.\n"

    text_box.delete("1.0", tk.END)
    text_box.insert(tk.END, output)


# simulate bcrypt cracking
def simulate_bcrypt():
    msg = simulate_bcrypt_attempt()
    text_box.delete("1.0", tk.END)
    text_box.insert(tk.END, msg)


# UI elements
tk.Label(root, text="Enter Password:", font=("Arial", 14)).pack(pady=5)

entry = tk.Entry(root, width=40, font=("Arial", 14))
entry.pack(pady=5)

tk.Button(root, text="Analyze + Hash Password", width=30, command=process_password).pack(pady=10)
tk.Button(root, text="Show SHA-1 Crack Results", width=30, command=show_john_results).pack(pady=5)
tk.Button(root, text="Simulate Bcrypt Crack", width=30, command=simulate_bcrypt).pack(pady=5)
tk.Button(root, text="Copy Terminal Command", width=30, command=copy_command).pack(pady=5)

text_box = scrolledtext.ScrolledText(root, width=80, height=25, font=("Arial", 11))
text_box.pack(pady=10)

root.mainloop()
