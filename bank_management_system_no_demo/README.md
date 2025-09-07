# Bank Management System (Flask + SQLite + HTML/CSS)

A lightweight banking demo you can run locally. Features:
- User registration & login (hashed passwords)
- Open multiple accounts per user
- Deposit, withdraw, transfer (atomic) between accounts
- Transaction history
- Admin panel to view users & accounts
- SQLite database (no server required)

## Quick start

1. **Install Python 3.10+**
2. Open a terminal in this folder and run:
   ```bash
   python -m venv venv
   venv\Scripts\activate   # on Windows (PowerShell)
   # source venv/bin/activate # on macOS/Linux
   pip install -r requirements.txt
   python app.py
   ```
3. Visit: http://127.0.0.1:5000

The app will create `bank.db` and ensure one admin account exists.

## Notes

- This is an educational sample, not production-grade banking software.
- No email/SMS, no KYC, no interest calculations, etc.
- CSRF protection and advanced access controls are minimal for simplicity.
- To reset the app, stop the server and delete `bank.db`.
