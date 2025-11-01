# Phishing Link Detector

A simple Python application that detects potentially malicious or phishing URLs based on domain patterns, keywords, and structural indicators. It provides quick feedback through a clean dark-mode graphical user interface (GUI) built with Tkinter.

## Features
- Analyzes URLs for suspicious keywords and symbols.  
- Detects fake domains and IP-based URLs.  
- Identifies phishing-related top-level domains (e.g., `.xyz`, `.pw`, `.tk`).  
- Displays detailed findings and overall risk level.  
- Minimalist Tkinter dark-mode interface.  

## Technologies Used
- **Python 3**  
- **Tkinter** (for GUI)  
- **re** (Regular Expressions for pattern detection)  

## How to Run
1. Clone this repository or download the project folder.  
2. Open the terminal or command prompt in the project directory.  
3. Run the program using:
   ```bash
   python phishing_detector.py
   ```
4. Enter a URL in the input field and click **Check Link** to analyze.  
5. Click **Clear** to reset the input and results.

## Example Output
| URL | Result |
|------|---------|
| `https://secure-login-account.com` | Suspicious |
| `http://192.168.0.1/login` | Likely Phishing |
| `https://github.com` | Likely Safe |

## Folder Structurecd /Users/janmarccoloma/Documents/MyProject/phishing-link-detector
git init
```
cybersecurity-projects/
│
└── phishing-link-detector/
    ├── README.md
    ├── phishing_detector.py
```

## Future Improvements
- Integrate live phishing database checks (e.g., Google Safe Browsing API).  
- Add confidence scoring or color-coded risk bars.  
- Include link history and exportable reports.  
