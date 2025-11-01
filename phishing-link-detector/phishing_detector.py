import re
import tkinter as tk
from urllib.parse import urlparse

# ---------- Detection Logic ----------
PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "signin", "webscr", "paypal", "ebay", "amazon"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".pw", ".info", ".gq", ".tk", ".ml"
]

def is_ip_address(domain):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) is not None

def contains_phishing_keywords(url):
    return any(keyword in url.lower() for keyword in PHISHING_KEYWORDS)

def has_suspicious_symbols(url):
    return '@' in url or url.count('-') > 3

def has_multiple_subdomains(domain):
    return domain.count('.') > 3

def has_suspicious_tld(domain):
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

def analyze_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    score = 0
    results = []

    if is_ip_address(domain):
        score += 2
        results.append("Domain is an IP address.")
    if contains_phishing_keywords(url):
        score += 2
        results.append("Contains phishing-related keywords.")
    if has_suspicious_symbols(url):
        score += 1
        results.append("Contains suspicious symbols (@ or too many '-').")
    if has_multiple_subdomains(domain):
        score += 1
        results.append("Has multiple subdomains.")
    if has_suspicious_tld(domain):
        score += 1
        results.append("Uses uncommon top-level domain.")
    
    if score >= 4:
        verdict = "Likely Phishing"
    elif 2 <= score < 4:
        verdict = "Suspicious"
    else:
        verdict = "Likely Safe"

    return verdict, results


# ---------- GUI Setup ----------
def on_analyze():
    url = url_entry.get().strip()
    if not url:
        result_label.config(text="Please enter a URL.")
        findings_box.config(state="normal")
        findings_box.delete(1.0, tk.END)
        findings_box.config(state="disabled")
        return

    verdict, findings = analyze_url(url)
    result_label.config(text=verdict)

    findings_box.config(state="normal")
    findings_box.delete(1.0, tk.END)
    if findings:
        for item in findings:
            findings_box.insert(tk.END, f"- {item}\n")
    else:
        findings_box.insert(tk.END, "No suspicious indicators found.")
    findings_box.config(state="disabled")


def clear_all():
    url_entry.delete(0, tk.END)
    result_label.config(text="")
    findings_box.config(state="normal")
    findings_box.delete(1.0, tk.END)
    findings_box.config(state="disabled")


# ---------- Window Layout ----------
window = tk.Tk()
window.title("Phishing Link Detector")
window.geometry("480x320")
window.config(bg="black")

# Title
title_label = tk.Label(
    window,
    text="Phishing Link Detector",
    font=("Segoe UI", 16, "bold"),
    bg="black",
    fg="white"
)
title_label.pack(pady=20)

# URL Input
url_entry = tk.Entry(
    window,
    width=50,
    font=("Segoe UI", 11),
    relief="flat",
    bd=0,
    highlightthickness=1,
    highlightbackground="white",
    highlightcolor="white",
    bg="#111111",
    fg="white",
    insertbackground="white"
)
url_entry.pack(pady=5, ipady=6)

# Buttons Frame
button_frame = tk.Frame(window, bg="black")
button_frame.pack(pady=8)

analyze_button = tk.Button(
    button_frame,
    text="Analyze",
    command=on_analyze,
    bg="white",
    fg="black",
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    width=12,
    height=1,
    activebackground="#f3f4f6",
    activeforeground="black"
)
analyze_button.pack(side="left", padx=5)

clear_button = tk.Button(
    button_frame,
    text="Clear",
    command=clear_all,
    bg="white",
    fg="black",   
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    width=8,
    height=1,
    activebackground="#f3f4f6",
    activeforeground="black"
)
clear_button.pack(side="left", padx=5)

# Verdict Label
result_label = tk.Label(
    window, text="", font=("Segoe UI", 12, "bold"), bg="black", fg="white"
)
result_label.pack(pady=10)

# Findings Box
findings_box = tk.Text(
    window,
    width=55,
    height=6,
    wrap="word",
    font=("Segoe UI", 10),
    state="disabled",
    bg="#0b0b0b",
    fg="white",
    relief="flat",
)
findings_box.pack(pady=5)

# Footer
footer_label = tk.Label(
    window,
    text="Cybersecurity Project • Python",
    bg="black",
    fg="#9ca3af",
    font=("Segoe UI", 9)
)
footer_label.pack(side="bottom", pady=10)

window.mainloop()
