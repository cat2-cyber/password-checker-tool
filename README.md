# password-checker-tool
A Python script to evaluate password strength and check if passwords have been compromised using the Pwned Passwords API.

## Features
- Validates password strength (length, complexity, etc.).
- Checks if passwords appear in known data breaches.
- Exports results to a CSV file.

## How to Use
1. Place your passwords in a text file (one password per line).
2. Update the `file_path` in the script with your file's location.
3. Run the script: `python password_checker.py`.
4. View the results in the console or exported CSV file.

## Requirements
- Python 3.x
- `requests` library (`pip install requests`)

## Disclaimer
Do not use this tool to check passwords that you don't own. Always handle sensitive data responsibly.
