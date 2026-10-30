PHISHGUARD AI - SETUP GUIDE
===========================

1. Install Python and VS Code.
2. Open this PhishGuard_AI folder in VS Code.
3. Open Terminal > New Terminal.
4. Create a virtual environment (Windows PowerShell):
       py -m venv venv
       .\venv\Scripts\Activate.ps1

   If PowerShell blocks activation, use Command Prompt terminal and run:
       venv\Scripts\activate.bat

5. Install packages:
       python -m pip install --upgrade pip
       pip install -r requirements.txt

6. Train the AI model (internet is needed for the first download):
       python train_model.py

7. Start the website:
       python app.py

8. Open this address in Chrome:
       http://127.0.0.1:5000

IMPORTANT:
- Keep the terminal open while using the website.
- Press Ctrl+C in the terminal to stop the local server.
- The model is trained on the UCI SMS Spam Collection dataset.
- This is an educational prototype. It may make mistakes and is not a replacement
  for checking messages through official sources.
- Uploaded files are processed locally by this app and saved message text is stored
  in the local SQLite database file phishguard.db.
- Do not upload messages containing real passwords, OTPs, account numbers, or other
  sensitive personal information.
