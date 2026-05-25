import tkinter as tk
from tkinter import scrolledtext, messagebox
import subprocess
import threading
import os

def run_cracker():
    password = entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password first!")
        return

    # Clear entry
    entry.delete(0, tk.END)

    # Clear previous output
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Running cracker...\n\n")
    # Run the C executable
    try:
        if not os.path.exists("a.exe"):
            messagebox.showerror("Error", "a.exe not found! Make sure it's in the same folder.")
            return

        process = subprocess.Popen(
            ["a.exe"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Send password and capture full output
        output, _ = process.communicate(input=password + "\n")

        # Display the EXACT same output as the C program
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, output)

    except Exception as e:
        output_text.insert(tk.END, f"Error: {e}\n")

# Run in thread to prevent GUI freeze
def start_test():
    threading.Thread(target=run_cracker, daemon=True).start()

# GUI Setup
root = tk.Tk()
root.title("Parallel Password Cracker")
root.geometry("900x700")
root.configure(bg="#1e1e1e")
root.resizable(True, True)

# Title
title = tk.Label(root, text="Parallel Password Cracker", font=("Courier", 20, "bold"), bg="#1e1e1e", fg="#00ff00")
title.pack(pady=20)

# Input frame
input_frame = tk.Frame(root, bg="#1e1e1e")
input_frame.pack(pady=10)

tk.Label(input_frame, text="Enter password to crack:", font=("Courier", 14), bg="#1e1e1e", fg="white").pack(side=tk.LEFT, padx=10)
entry = tk.Entry(input_frame, font=("Courier", 14), width=40, show="*", bg="#333", fg="white", insertbackground="white")
entry.pack(side=tk.LEFT, padx=10)
entry.focus()

# Test button
btn = tk.Button(root, text="Start Cracking", font=("Courier", 16, "bold"), bg="#00aa00", fg="white",
                activebackground="#00ff00", command=start_test, cursor="hand2")
btn.pack(pady=20)

# Output text box (like console)
output_text = scrolledtext.ScrolledText(root, font=("Courier", 12), bg="black", fg="#00ff00", 
                                       insertbackground="white", wrap=tk.WORD, padx=10, pady=10)
output_text.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

# Initial message
output_text.insert(tk.END, "Ready. Enter a password and click 'Start Cracking'.\n")
output_text.insert(tk.END, "The output will appear here exactly as in the C console version.\n\n")

root.mainloop()