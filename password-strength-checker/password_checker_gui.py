import tkinter as tk
import re

# ---------- Common Weak Passwords ----------
COMMON_PASSWORDS = ["password", "123456", "qwerty", "abc123", "iloveyou", "admin"]

# ---------- Password Strength Logic ----------
def check_password_strength(password):
    score = 0

    if len(password) < 8:
        return "Too short! Use at least 8 characters.", "red"

    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1

    if password.lower() in COMMON_PASSWORDS:
        return "This is a very common password.", "red"

    if score <= 2:
        return "Weak password", "red"
    elif score == 3:
        return "Moderate password", "orange"
    else:
        return "Strong password", "#64ffda"


# ---------- GUI Functions ----------
def evaluate_password():
    password = entry.get().strip()
    if not password:
        result_label.config(text="Please enter a password.", fg="gray")
        return

    message, color = check_password_strength(password)
    result_label.config(text=message, fg=color)


def toggle_password_visibility():
    if entry.cget("show") == "*":
        entry.config(show="")
        toggle_button.config(text="Hide")
    else:
        entry.config(show="*")
        toggle_button.config(text="Show")


def clear_all():
    entry.delete(0, tk.END)
    result_label.config(text="")
    entry.focus_set()


# ---------- Window Layout ----------
window = tk.Tk()
window.title("Password Strength Checker")
window.geometry("460x280")
window.resizable(False, False)
window.config(bg="#0a192f")

# Title
title_label = tk.Label(
    window,
    text="Password Strength Checker",
    font=("Segoe UI", 16, "bold"),
    bg="#0a192f",
    fg="#64ffda"
)
title_label.pack(pady=20)

# Entry Frame
entry_frame = tk.Frame(window, bg="#0a192f")
entry_frame.pack(pady=5)

entry = tk.Entry(
    entry_frame,
    width=35,
    font=("Segoe UI", 12),
    show="*",
    relief="flat",
    bd=2,
    highlightthickness=1,
    highlightbackground="#64ffda",
    highlightcolor="#64ffda",
    bg="#112240",
    fg="white",
    insertbackground="white"
)
entry.grid(row=0, column=0, ipady=6, padx=(0, 5))

toggle_button = tk.Button(
    entry_frame,
    text="Show",
    command=toggle_password_visibility,
    font=("Segoe UI", 10),
    bg="#0a192f",
    fg="#0a192f",
    relief="flat",
    activebackground="#0a192f",
    activeforeground="white",
    width=6
)
toggle_button.grid(row=0, column=1)

# Buttons Frame
button_frame = tk.Frame(window, bg="#0a192f")
button_frame.pack(pady=15)

check_button = tk.Button(
    button_frame,
    text="Check Strength",
    command=evaluate_password,
    bg="#64ffda",
    fg="#0a192f",
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    width=15,
    height=1
)
check_button.pack(side="left", padx=5)

clear_button = tk.Button(
    button_frame,
    text="Clear",
    command=clear_all,
    bg="#64ffda",
    fg="#0a192f",
    font=("Segoe UI", 10),
    relief="solid",
    bd=1,
    width=10,
    height=1,
)
clear_button.pack(side="left", padx=5)

# Result Label
result_label = tk.Label(
    window,
    text="",
    font=("Segoe UI", 12, "bold"),
    bg="#0a192f",
    fg="white"
)
result_label.pack(pady=15)

# Footer
footer_label = tk.Label(
    window,
    text="Cybersecurity Project • Python",
    bg="#0a192f",
    fg="#6b7280",
    font=("Segoe UI", 9)
)
footer_label.pack(side="bottom", pady=10)

window.mainloop()
