import tkinter as tk
from tkinter import messagebox
import re

# Common weak passwords
common_passwords = ["password", "123456", "qwerty", "abc123", "iloveyou", "admin"]

def check_password_strength(password):
    score = 0

    if len(password) < 8:
        return "Too short! Use at least 8 characters."

    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1

    if password.lower() in common_passwords:
        return "This is a very common password!"

    if score <= 2:
        return " Weak password "
    elif score == 3:
        return " Moderate password "
    else:
        return " Strong password "

# ---- GUI setup ----
def evaluate_password():
    password = entry.get()
    result = check_password_strength(password)

    if "Weak" in result:
        result_label.config(text=result, fg="red")
    elif "Moderate" in result:
        result_label.config(text=result, fg="orange")
    elif "Strong" in result:
        result_label.config(text=result, fg="lime")
    else:
        result_label.config(text=result, fg="white")

# Main window
window = tk.Tk()
window.title("Password Strength Checker 🔐")
window.geometry("400x250")
window.resizable(False, False)
window.config(bg="#0a192f")

# Labels and input
title_label = tk.Label(window, text="Password Strength Checker", font=("Arial", 14, "bold"), bg="#0a192f", fg="#64ffda")
title_label.pack(pady=15)

entry_label = tk.Label(window, text="Enter your password:", font=("Arial", 11), bg="#0a192f", fg="white")
entry_label.pack()

entry = tk.Entry(window, width=30, show="*", font=("Arial", 12))
entry.pack(pady=5)

check_button = tk.Button(window, text="Check Strength", command=evaluate_password, font=("Arial", 11, "bold"), bg="#64ffda", fg="#0a192f")
check_button.pack(pady=10)

result_label = tk.Label(window, text="", font=("Arial", 12, "bold"), bg="#0a192f", fg="white")
result_label.pack(pady=10)

# Run the app
window.mainloop()
