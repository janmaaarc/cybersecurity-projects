# Password Strength Checker

A simple Python application that evaluates the strength of a user's password based on length, character variety, and common password patterns. It provides real-time feedback through a clean graphical user interface (GUI) built with Tkinter.

## Features
- Checks password length and complexity.  
- Detects the presence of uppercase, lowercase, numbers, and symbols.  
- Identifies common weak passwords (e.g., `password`, `123456`, etc.).  
- Displays strength levels: **Weak**, **Moderate**, or **Strong**.  
- User-friendly Tkinter interface.  

## Technologies Used
- **Python 3**  
- **Tkinter** (for GUI)  
- **re** (Regular Expressions for password validation)  

## How to Run
1. Clone this repository or download the project folder.  
2. Open the terminal or command prompt in the project directory.  
3. Run the program using:
   ```bash
   python password_checker.py
   ```
4. Enter a password in the input field and click **Check Strength** to evaluate.

## Example Output
| Password | Result |
|-----------|---------|
| `abc123` | Weak password |
| `Abc12345` | Moderate password |
| `Abc123!@#` | Strong password |

## Folder Structure
```
cybersecurity-projects/
│
└── password-strength-checker/
    ├── password_checker.py
    ├── README.md
    ├── requirements.txt
```

## Future Improvements
- Add a password generator tool.  
- Include entropy-based scoring.  
- Save password history for analysis.
